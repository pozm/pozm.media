const express = require('express')
const path = require('path');
const fs = require('fs')
const mysql = require('mysql')
const rateLimit = require("express-rate-limit");
const bodyParser = require('body-parser');
const {mysqlPassWord, SessionKey, recapSiteKey} = require('./keys');
const session = require('express-session')
const crypto = require('crypto');
const multer = require('multer');
const got = require('got');
var MySQLStore = require('express-mysql-session')(session);


let cache = {}


const limiter = rateLimit({
    windowMs: 180e3, 
    max: 15 
});

let upload = multer();

let con = mysql.createConnection({
    host: "localhost",
    user: "root",
    password: mysqlPassWord
})


con.connect(function(err) {
    if (err) throw err;
    console.log("Connected! (My sql) ");
});

const app = express()

app.use('/', express.static(path.join(__dirname, 'html'), {extensions:['html']}))
app.use('/media', express.static(path.join(__dirname, 'media'), {extensions:['png','jpeg','mp4']}))
app.set('trust proxy', true)
app.set('view engine', 'ejs');
app.set('views',path.join(__dirname, 'views'))
app.use(bodyParser.json({ extended: true, limit:'10kb' }))
app.use(bodyParser.urlencoded({ extended: false,limit:'10kb',parameterLimit:100 }));
app.use(upload.array());


// app.use('/IsGay*',limiter)
app.use('/api/',limiter)

con.query('create database if not exists sessions')

var sessionStore = new MySQLStore({
    
    host:'localhost',
    port:3306,
    user:'root',
    password:mysqlPassWord,
    database:'sessions'
    
});

app.use(session({
    store: sessionStore,
    secret: SessionKey,
    resave: false,
    saveUninitialized: false,
    cookie: { secure: "auto", 'expires' : 1000 * 60 * 60 * 24 * 30000},
    name: 'session'
}))

/* app.use((req,res,next) => {
    if (!req.session.accessed && !req.session.logedInto && req.path !='/getScript' && !req.path.includes('api')){
        req.session.accessed = true;
        return res.send('<script>window.location.reload()</script>')
    }
    next()
})
 */

const scriptsMetaData = JSON.parse(fs.readFileSync('p-Scripts/meta.json'))
const SynapseFixes = JSON.parse(fs.readFileSync('Utility/SyanpseFixes.json'))


const dataStructures = {

    account:`CREATE TABLE if not exists \`whitelist\`.\`account\` (
        \`id\` int NOT NULL AUTO_INCREMENT,
        \`username\` varchar(15) NOT NULL,
        \`password\` text NOT NULL,
        \`email\` text NOT NULL,
        \`registeredAt\` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
        \`powerId\` int NOT NULL DEFAULT '0',
        \`subscriptions\` json,
        PRIMARY KEY (\`id\`)
    )`,
    accountPWReset:`create table if not exists \`whitelist\`.\`PWreset\`(
        \`id\` varchar(255) NOT NULL,
        \`userid\` INT NOT NULL,
        \`expires\` DATE NULL,
        PRIMARY KEY (\`id\`),
        UNIQUE INDEX \`id_UNIQUE\` (\`id\` ASC),
        UNIQUE INDEX \`userid_UNIQUE\` (\`userid\` ASC));
    `,
    gay:`CREATE TABLE if not exists \`is-gay\`.\`gay\` (
        \`user\` VARCHAR(255) NOT NULL,
        \`id\` VARCHAR(45) NOT NULL,
        \`by\` VARCHAR(255) NOT NULL,
        \`reason\` VARCHAR(255) NOT NULL DEFAULT 'They are gay',
        \`at\` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (\`id\`),
        UNIQUE INDEX \`id_UNIQUE\` (\`id\` ASC));
    `

}

con.query(`create database if not exists whitelist;`)
con.query(`create database if not exists \`is-gay\`;`)
con.query(`${dataStructures.account};`)
con.query(`${dataStructures.accountPWReset};`)
con.query(`${dataStructures.gay};`)



function shouldcache(c) {
    return true;
    if (!c) return true
    return (( new Date().getTime() - c.t.getTime()) > 5e6)
}


async function getDataFromId (id) {
    if (!id) return null;
    let n = (arguments[1] ?? arguments[0]).toString()
    let v = cache[n]

    let should = shouldcache(v)

    if (should) {
        return new Promise(res => {
            
            con.query('select * from `whitelist`.`account` where id = ?',id, (err, res2) => {
                
                if (err) throw err
                if (0 in res2) {
                    cache[id.toString()] = {v:res2[0],t:new Date()};
                    return res( res2[0])
                }
                res(null)
            })
            
                
        })
    } else return v.v
        
}
    
    
async function AsyncQuery(cache2,query,args) {
    
    let n = (cache2 ?? args ?? query).toString()
    let v = cache[n]

    let should = shouldcache(v)

    if (should||cache2) {
        return new Promise(resolve => {
            
            func = (err,result)=>{
                
                if (err) throw err
                cache[n] = {v:result,t:new Date()};
                return resolve(result)
                
            }
            con.query(query,args ?? func, func)
            
        })
    } else return v.v
    
}



// front end


app.get('/', async (req,res) => {
    
    let data = await getDataFromId(req.session.logedInto ?? '')
    res.render('index',{data : data ? data : false})
})

app.get('/login', async (req,res) => {
    
    let data = await getDataFromId(req.session.logedInto ?? '')
    if (data) return res.redirect('/')
    
    res.render('login',{signedInto : data ? data.username : false})
})
app.get('/signup', async (req,res) => {
    
    let data = await getDataFromId(req.session.logedInto ?? '')

    if (data) return res.redirect('/')
    
    res.render('signup',{signedInto : data ? data.username : false})
})

app.get('/admin', async (req,res) => {
    
    let data = await getDataFromId(req.session.logedInto ?? '')
    if (!data) return res.status(401).sendFile(path.join(__dirname, 'html/errors/401.html'))
    if (data.powerId < 5) return res.status(401).sendFile(path.join(__dirname, 'html/errors/401.html'))
    let tables = await AsyncQuery(false,'select * from `whitelist`.`account`')
    
    res.render('admin',{data : data ? data : false, reg : tables})
})
app.get('/SSG', async (req,res) => {
    
    let data = await getDataFromId(req.session.logedInto ?? '')
    if (!data) return res.status(401).sendFile(path.join(__dirname, 'html/errors/401.html'))
    if (data.powerId < 2) return res.status(401).sendFile(path.join(__dirname, 'html/errors/401.html'))
    res.render('ssg',{data : data ? data : false, fixes : SynapseFixes.Fixes})
})


app.get('/getScript', async (req, res) => {

    if (!req.query.script) {
        res.status(400).send('Bad Request.')
        return;
    }
    let scr = req.query.script
    if (!scriptsMetaData[scr]) {
        res.status(400).send('Bad Request.')
        // console.log('1')
        return;
    }
    let data = await getDataFromId(req.session.logedInto ?? '')
    // console.log(data,req.session.logedInto)
    if (scriptsMetaData[scr].power > 0 && (! data) ) return res.sendStatus(401)
    if (data.powerId < scriptsMetaData[scr].power) return res.sendStatus(401)
    res.sendFile(path.join(__dirname,'p-Scripts/'+scriptsMetaData[scr].url))

})
    
    
    //api / backend
    
async function getIdFromUser (user) {

    return new Promise(res => {

        con.query('select id from `whitelist`.`account` where username = ?',user, (err, res2) => {

            if (err) throw err
            if (0 in res2) return res( res2[0].id)
            res(false)
        })


    })

}



app.patch('/admin/UpdatePower', async (req,res) => {

    let data = await getDataFromId(req.session.logedInto ?? '')
    if (!data) return res.status(401).sendFile(path.join(__dirname, 'html/errors/401.html'))
    if (data.powerId < 5 ) return res.status(401).sendFile(path.join(__dirname, 'html/errors/401.html'))
    let {id,power} = req.body
    let data2 = await getDataFromId(id ?? '')
    if (!data2) return res.sendStatus(400)
    if (power >= data.powerId) return res.status(401).sendFile(path.join(__dirname, 'html/errors/401.html'))
    // console.log(power,id)
    await AsyncQuery(id,'update `whitelist`.`account` set powerId = ? where id = ?',[power,id])
    return res.json({message:'Successfully updated'})
})

app.post('/admin/GPWR', async (req,res) => {

    let data = await getDataFromId(req.session.logedInto ?? '')
    if (!data) return res.status(401).sendFile(path.join(__dirname, 'html/errors/401.html'))
    if (data.powerId < 5 ) return res.status(401).sendFile(path.join(__dirname, 'html/errors/401.html'))
    let {id,expires} = req.body
    let data2 = await getDataFromId(id ?? '')
    if (!data2) return res.sendStatus(400)
    if (data2.powerId >= data.powerId) return res.status(401).sendFile(path.join(__dirname, 'html/errors/401.html'))
    let Rid = crypto.createHash('sha512').update(Math.floor(Math.random() * 1e20).toString()).digest('base64')
    await AsyncQuery(id,'insert into \`whitelist\`.\`PWreset\` (id,userid,expires) values (?,?,?)', [Rid,data2.powerId,expires ?? '9999-01-01'])
    return 

})

app.delete('/admin/AccountDelete', async (req,res) => {


    let data = await getDataFromId(req.session.logedInto ?? '')
    if (!data) return res.status(401).sendFile(path.join(__dirname, 'html/errors/401.html'))
    if (data.powerId < 5 ) return res.status(401).sendFile(path.join(__dirname, 'html/errors/401.html'))
    let {id} = req.body
    let data2 = await getDataFromId(id ?? '')
    if (!data2) return res.sendStatus(400)
    if (data2.powerId >= data.powerId) return res.status(401).sendFile(path.join(__dirname, 'html/errors/401.html'))
    // console.log(id)
    await AsyncQuery(id,'delete from `whitelist`.`account` where id = ?',id)
    return res.json({message:'Successfully deleted'})
})

app.get('/api/logout', (req,res) => {

    req.session.destroy()
    res.send('<script>window.location.replace("/")</script>')

})

app.post('/api/LogintoAccount', (req,res) => {
    
    req.session.cool = true
    let {username,password} = req.body
    if (!password) return res.status(400).send(JSON.stringify({error:19,message:'Missing credentials'}))
    if (!username) return res.status(400).send(JSON.stringify({error:19,message:'Missing credentials'}))
    con.query(dataStructures.account)
    hash = crypto.createHash('sha512')
        .update(password)
    let digested = hash.digest('hex')
    // console.log(digested)
    con.query('select * from `whitelist`.`account` where password = ? and (username = ? or email = ?)', [digested, username ?? '', username ?? ''], (err,resi) => {
        if (err) throw err
        if (0 in resi) {
            req.session.logedInto = resi[0].id
            res.send(JSON.stringify({error : false, message : 'Logged in'}))
        }
        else {
            res.status(401).json({error:6, message:'Invalid credentials'})
        }
    })
})



app.post('/api/CreateAccount', async (req,res) => {

    if (!req.body['g-recaptcha-response']) return res.json({error:21,message:'Please complete the recaptcha'})

    var verificationUrl = "https://www.google.com/recaptcha/api/siteverify?secret=" + recapSiteKey + "&response=" + req.body['g-recaptcha-response'] + "&remoteip=" + req.connection.remoteAddress;

    let resb = JSON.parse((await got(verificationUrl)).body)

    if (!resb.success) return res.json({error:21,message:'You have failed the recaptcha, try again?'})

    let {username,password,email} = req.body
    if (! username||!password||!email) return res.status(400).send(JSON.stringify({error:19,message:'Missing credentials'}))

    if (!email.match(/.{0,64}[@](\w{0,255}[.])\w{0,10}/)) return res.status(400).send(JSON.stringify({'error':3,message:'bad email'}))
    if (username.match(/(.{30,}|[^A-Za-z\d])/)) return res.status(400).send(JSON.stringify({'error':4,message:'bad username'}))
    if (!password.match(/^[\x00-\x7F]{8,32}$/i)) return res.status(400).send(JSON.stringify({'error':7,message:'password is invalid'}))
    con.query('select * from `whitelist`.`account` where username = ? or email = ?', [username,email], async (err , resu) => {

        if (err) throw err
        if (0 in resu) {

            return res.send(JSON.stringify({'error' : 10, message: `${0 in resu.filter(v => v.email == email) ? 'Email' : 'Username'} is already in use.`}))

        }
        else {

            hash = crypto.createHash('sha512')
                .update(password)

            await AsyncQuery(null,'insert into \`whitelist\`.\`account\` (username,password,email,registerIp) values (?, ?, ?, ?)', [username,hash.digest('hex'),email, req.ip])
            req.session.logedInto = await getIdFromUser(username)
            delete cache[req.session.logedInto]
            res.send(JSON.stringify({'message':'sucessfully logged in'}))

        }

    })

})

//profiles
/** @todo make profiles, will probably do in some date later. if i even decide to keep. */

app.get('/user/:id', async (req,res)=>{

    let data = getDataFromId(req.param.id)
    if (!data) return res.status(404).sendFile(path.join(__dirname, 'html/errors/404.html'))
})

// others

app.get('/WebhookTools', (req,res)=>{

    res.render('WebhookM')

})

app.get('/contact', (req,res)=>{

    res.render('contact')

})
app.get('/byeLS',(rq,rs)=>{
    rs.render('bls')
})

//meme shit


app.get('/name', (req,res)=>{

    res.render('GenerateName')

})

app.patch('/api/EditGay', async(req,res)=>{

    let data = await getDataFromId(req.session.logedInto ?? '')
    if (!data) return res.status(401).sendFile(path.join(__dirname, 'html/errors/401.html'))
    let user = req.body.user
    let reason = req.body.reason || 'He is gay.'
    let id = req.body.id
    if (!user) res.status(400).json({error:142,message:'no user'})
    if (!id) res.status(400).json({error:143,message:'no id'})
    let test = user.match(/\S/gi) ?? ['']
    if (user.match(/(pozm|p0zm|p()zm|nukebot|brad|br@d)/gi) || user.match(/[^!-~ ]/gm) || test.join('') == 'pozm' || user.match(/(p.*?(o|0|()).*?z.*?m?)/gmi) || user.match(/(b.*?r.*?(a|@).*?d?)/gmi)) return res.status(400).json({error:101,message:'includes banned words'})

    let resp = await AsyncQuery(true,'select `gay`.`by` from `is-gay`.`gay` where `id` = ?', id)
    if(resp[0]?.by != data.username) return res.status(401).sendFile(path.join(__dirname, 'html/errors/401.html'));
    await AsyncQuery(true,'update `is-gay`.`gay` set user=?,reason=? where id = ?', [user,reason,id])
    res.json({error:false,message:'Successfully updated'})
})

app.get('/IsGay/:id', async (req,res)=>{

    // console.log(req.params.id)

    if (req.params.id == 'logs') {


        return;
    }
    let data = await getDataFromId(req.session.logedInto ?? '')
    let resp = await AsyncQuery(true,'select `gay`.\`user\`,`gay`.\`reason\`,`gay`.`by` from `is-gay`.`gay` where `id` = ?', req.params.id)
    if (!resp[0]) return res.status(404).sendFile(path.join(__dirname, 'html/errors/404.html'))
    // console.log(resp)
    res.render('TemplateIsGay', {...resp[0], id:req.params.id,data:data})

})
function uuidv4() {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
        var r = Math.random() * 16 | 0, v = c == 'x' ? r : (r & 0x3 | 0x8);
        return v.toString(16);
    });
}
  
app.post('/api/createGay', async (req,res)=>{

    let data = await getDataFromId(req.session.logedInto ?? '')
    if (!data) return res.sendStatus(401)
    if (data.powerId < 1 ) return res.sendStatus(401) 
    let user = req.body.user
    let reason = req.body.reason || 'He is gay.'
    if (!user) res.status(400).json({error:142,message:'no user'})

    let test = user.match(/\S/gi) ?? ['']
    if (user.match(/(pozm|p0zm|p()zm|nukebot|brad|br@d)/gi) || user.match(/[^!-~ ]/gm) || test.join('') == 'pozm' || user.match(/(p.*?(o|0|()).*?z.*?m)/gmi) || user.match(/(b.*?r.*?(a|@).*?d)/gmi)) return res.status(400).json({error:101,message:'includes banned words'})
    let id = uuidv4()
    let resu = await AsyncQuery(id,'insert into \`is-gay\`.\`gay\` (\`user\`,\`id\`,\`by\`,\`reason\`) values (?, ?, ?, ?)', [user,id,data.username,reason])
    res.redirect('/IsGay/'+id)
})
app.get('/IsGay', async (req,res) => {

    let data = await getDataFromId(req.session.logedInto ?? '')
    if (!data) return res.status(401).sendFile(path.join(__dirname, 'html/errors/401.html'))
    if (data.powerId <= 1) return res.status(401).sendFile(path.join(__dirname, 'html/errors/401.html'))
    return res.render('makeIsGay',{data : data ? data : false})

})
//404 catching

app.get('*', (req, res) => {
    res.status(404)
    res.sendFile(path.join(__dirname, 'html/errors/404.html'))
});

app.listen(80, () => {console.log('now running')})