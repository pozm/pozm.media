const express = require('express')
const path = require('path');
const fs = require('fs')
const mysql = require('mysql')
const rateLimit = require("express-rate-limit");
const bodyParser = require('body-parser');
const {mysqlPassWord} = require('./keys')


const limiter = rateLimit({
    windowMs: 60e3, 
    max: 10 
});


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
app.use('/IsGay',limiter)

app.get('/getScript', (req, res) => {

    if (!req.query.script) {
        res.status(400).send('Bad Request.')
        return;
    }
    let f = path.join(__dirname, `p-Scripts/${req.query.script}.js`);
    if (!fs.existsSync(f)) return res.status(400).send('Bad Request.')
    res.sendFile(f)

})

app.post('/api/CreateAccount', (req,res) => {

    console.log(req.body)
    let {username,password,key} = req.body
    if (! username||!password||!key) return res.sendStatus(400)

    con.query('create database if not exists whitelist')
    con.query('use whitelist')
    con.query(`CREATE TABLE if not exists \`whitelist\`.\`keycode\` (
        \`id\` INT primary key NOT NULL AUTO_INCREMENT,
        \`key\` VARCHAR(255) NOT NULL,
        \`registered\` bool NOT NULL DEFAULT false,
        \`createdAt\` TIMESTAMP NULL DEFAULT current_timestamp
        )
    `)
    con.query('select * from keycode where "key" = ?',key, (err,resul,fe) => {
        if (! 0 in resul) return res.sendStatus(401)
    })

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


    if (req.headers["user-agent"] == 'python-requests/2.23.0' || ! req.headers.cookie) return res.sendStatus(403)

    let user = req.query.user
    let reason = req.query.reason ?? 'He is gay.'
    if (!user) return res.sendStatus(403)
    try {user = decodeURI(user)} catch (e) {return res.send('fuck off u entered a bad url') }

    let test = user.match(/\S/gi) ?? ['']
    let send = true;
    if (user.match(/(pozm|p0zm|p()zm|nukebot)/gi) || user.match(/[^!-~ ]/gm) || test.join('') == 'pozm' || user.match(/(p.*?(o|0|()).*?z.*?m?)/gmi)) {
        res.sendStatus(403); 
        console.log(user, 'was just attempted'); 
        send = false;
    } 
    if (send) res.render('TemplateIsGay', {user: user, reason : reason})
    //console.log(req.headers)
    con.query('create database if not exists IsGayGlobalLogs')
    con.query('use IsGayGlobalLogs')
    con.query('create table if not exists log (id int primary key auto_increment,  entered  text, at timestamp default current_timestamp, passed bool)')
    try {con.query('insert into log (entered, passed) values (?,?)', [ encodeURIComponent( user ),send])} catch(e) {}

})

app.get('/IsGayLog', (req,res) => {

    con.query('create database if not exists IsGayGlobalLogs')
    con.query('use IsGayGlobalLogs')
    con.query('select * from log', (err,resu)=>{
        if (err) throw err;
        //console.log(resu)
        res.render('IsGayLogs', {logs: resu})
    })

})


//404 catching

app.get('*', (req, res) => {
    res.status(404)
    res.sendFile(path.join(__dirname, 'html/errors/404.html'))
});

app.listen(80, () => {console.log('now running')})