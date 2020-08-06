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
const got = require('got')
var MySQLStore = require('express-mysql-session')(session);

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
    console.log("Connected!");
});

const app = express()

app.use('/', express.static(path.join(__dirname, 'html'), {extensions:['html']}))
app.set('trust proxy', true)
app.set('view engine', 'ejs');
app.use(bodyParser.json({ extended: true }))
app.use(bodyParser.urlencoded({ extended: false }));
app.use(upload.array());

app.use('/IsGay',limiter)
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
    cookie: { secure: false, 'expires' : 1000 * 60 * 60 * 24 * 30000},
    name: 'session'
}))

const scriptsMetaData = JSON.parse(fs.readFileSync('p-Scripts/meta.json'))
const SynapseFixes = JSON.parse(fs.readFileSync('Utility/SyanpseFixes.json'))


const dataStructures = {

    account:`CREATE TABLE if not exists \`account\` (
        \`id\` int NOT NULL AUTO_INCREMENT,
        \`username\` varchar(15) NOT NULL,
        \`password\` text NOT NULL,
        \`email\` text NOT NULL,
        \`registeredAt\` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
        \`powerId\` int NOT NULL DEFAULT '0',
        \`subscriptions\` json,
        PRIMARY KEY (\`id\`)
    )`,
    IsGayLogging:`create table if not exists log (id int primary key auto_increment,  entered  text, at timestamp default current_timestamp, passed bool)`

}



async function getDataFromId (id) {
    
    return new Promise(res => {
        
        con.query('create database if not exists whitelist')
        con.query('use whitelist')
        con.query(dataStructures.account)
        
        con.query('select * from `whitelist`.`account` where id = ?',id, (err, res2) => {
            
            if (err) throw err
            if (0 in res2) return res( res2[0])
            res(null)
        })
        
            
    })
        
}
    
    
async function AsyncQuery() {
    
    return new Promise(resolve => {
        
        func = (err,result)=>{
            
            if (err) throw err
            resolve(result)
            
        }
        con.query(arguments[0],arguments[1] ?? func, func)
        
    })
    
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
    let tables = await AsyncQuery('select * from `whitelist`.`account`')
    
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
        console.log('1')
        return;
    }
    let data = await getDataFromId(req.session.logedInto ?? '')
    console.log(data,req.session.logedInto)
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

app.post('/admin/UpdatePower', async (req,res) => {

    let data = await getDataFromId(req.session.logedInto ?? '')
    if (!data) return res.status(401).sendFile(path.join(__dirname, 'html/errors/401.html'))
    if (data.powerId < 5 ) return res.status(401).sendFile(path.join(__dirname, 'html/errors/401.html'))
    let {id,power} = req.body
    let data2 = await getDataFromId(id ?? '')
    if (!data2) return res.sendStatus(400)
    if (power > data.powerId) return res.status(401).sendFile(path.join(__dirname, 'html/errors/401.html'))
    console.log(power,id)
    await AsyncQuery('update `whitelist`.`account` set powerId = ? where id = ?',[power,id])
    return res.json({message:'Successfully updated'})
})

app.delete('/admin/AccountDelete', async (req,res) => {


    let data = await getDataFromId(req.session.logedInto ?? '')
    if (!data) return res.status(401).sendFile(path.join(__dirname, 'html/errors/401.html'))
    if (data.powerId < 5 ) return res.status(401).sendFile(path.join(__dirname, 'html/errors/401.html'))
    let {id} = req.body
    let data2 = await getDataFromId(id ?? '')
    if (!data2) return res.sendStatus(400)
    if (data2.powerId >= data.powerId) return res.status(401).sendFile(path.join(__dirname, 'html/errors/401.html'))
    console.log(id)
    await AsyncQuery('delete from `whitelist`.`account` where id = ?',id)
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
    if (! username) return res.status(400).send(JSON.stringify({error:19,message:'Missing credentials'}))
    
    con.query('create database if not exists whitelist')
    con.query('use whitelist')
    con.query(dataStructures.account)
    hash = crypto.createHash('sha512')
        .update(password)
    let digested = hash.digest('hex')
    console.log(digested)
    con.query('select * from `whitelist`.`account` where password = ? and (username = ? or email = ?)', [digested, username ?? '', username ?? ''], (err,resi) => {
        if (err) throw err
        if (0 in resi) {

            req.session.logedInto = resi[0].id
            res.send(JSON.stringify({error : false, message : 'Logged in'}))
        }
        else {
            res.status(401).send(JSON.stringify({error:6, message:'Invalid credentials'}))
        }
    })
})



app.post('/api/CreateAccount', async (req,res) => {

    console.log(req.body)

    if (!req.body['g-recaptcha-response']) return res.json({error:21,message:'Please complete the recaptcha'})

    var verificationUrl = "https://www.google.com/recaptcha/api/siteverify?secret=" + recapSiteKey + "&response=" + req.body['g-recaptcha-response'] + "&remoteip=" + req.connection.remoteAddress;

    let resb = JSON.parse((await got(verificationUrl)).body)

    console.log(resb)

    if (!resb.success) return res.json({error:21,message:'You have failed the recaptcha, try again?'})

    let {username,password,email} = req.body
    if (! username||!password||!email) return res.status(400).send(JSON.stringify({error:19,message:'Missing credentials'}))

    if (!email.match(/.{0,64}[@](\w{0,255}[.])\w{0,10}/)) return res.status(400).send(JSON.stringify({'error':3,message:'bad email'}))
    if (username.match(/(.{30}|[^A-Za-z\d])/)) return res.status(400).send(JSON.stringify({'error':4,message:'bad username'}))
    if (!password.match(/(.{32}|^[\x00-\x7F]+$)/)) return res.status(400).send(JSON.stringify({'error':7,message:'password is invalid'}))

    con.query('create database if not exists whitelist')
    con.query('use whitelist')
    con.query(dataStructures.account)
    con.query('select * from `whitelist`.`account` where username = ? or email = ?', [username,email], (err , resu) => {

        if (err) throw err
        if (0 in resu) {

            return res.send(JSON.stringify({'error' : 10, message: `${0 in resu.filter(v => v.email == email) ? 'Email' : 'Username'} is already in use.`}))

        }
        else {

            hash = crypto.createHash('sha512')
                .update(password)

            con.query('insert into account (username,password,email) values (?, ?, ?)', [username,hash.digest('hex'),email], async(err,resu,fie) => {
                if (err) throw err
                req.session.logedInto = await getIdFromUser(username)
                res.send(JSON.stringify({'message':'sucessfully logged in'}))
            })

        }

    })

/*     con.query(`CREATE TABLE if not exists \`whitelist\`.\`keycode\` (
        \`id\` INT primary key NOT NULL AUTO_INCREMENT,
        \`key\` VARCHAR(255) NOT NULL,
        \`registered\` bool NOT NULL DEFAULT false,
        \`createdAt\` TIMESTAMP NULL DEFAULT current_timestamp
        )
    `)
    con.query('select * from keycode where "key" = ?',key, (err,resul,fe) => {
        if (! 0 in resul) return res.sendStatus(401)
    }) */

})



function toByteCode(s) {

    let r = ''
    for (let v of s) {
        r+= v.charCodeAt(0)
    }
    return r
}

//meme shit

app.get('/IsGay', (req,res) => {


    if (req.headers["user-agent"] == 'python-requests/2.23.0' /* || ! req.headers.cookie  */) return res.sendStatus(403)

    let user = req.query.user
    let reason = req.query.reason ?? 'He is gay.'
    if (!user) return res.render('makeIsGay')
    try {user = decodeURI(user)} catch (e) {return res.render('makeIsGay') }

    let test = user.match(/\S/gi) ?? ['']
    let send = true;
    if (user.match(/(pozm|p0zm|p()zm|nukebot|brad|br@d)/gi) || user.match(/[^!-~ ]/gm) || test.join('') == 'pozm' || user.match(/(p.*?(o|0|()).*?z.*?m?)/gmi) || user.match(/(b.*?r.*?(a|@).*?d?)/gmi)) {
        res.sendStatus(403); 
        console.log(user, 'was just attempted'); 
        send = false;
    } 
    if (send) res.render('TemplateIsGay', {user: user, reason : reason})
    //console.log(req.headers)
    con.query('create database if not exists IsGayGlobalLogs')
    con.query('use IsGayGlobalLogs')
    con.query(dataStructures.IsGayLogging)
    try {con.query('insert into log (entered, passed) values (?,?)', [ encodeURIComponent( user ),send])} catch(e) {}

})

app.get('/IsGay/Log', (req,res) => {

    con.query('create database if not exists IsGayGlobalLogs')
    con.query('use IsGayGlobalLogs')
    con.query(dataStructures.IsGayLogging)
    con.query('select * from log', (err,resu)=>{
        if (err) throw err;
        //console.log(resu)
        res.render('IsGayLogs', {logs: resu})
    })

})

app.get('/cool', (req,res) => {

    console.log(req.ips ?? req.ip)
    res.send('hi')

})


//404 catching

app.get('*', (req, res) => {
    res.status(404)
    res.sendFile(path.join(__dirname, 'html/errors/404.html'))
});

app.listen(80, () => {console.log('now running')})