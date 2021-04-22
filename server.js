require('dotenv').config()
const express = require('express')
const bodyParser = require('body-parser')
const morgan = require('morgan')
const cors = require("cors")
const app = express()

const productRouter = require('./router/product')
const orderRouter = require('./router/order')

require('./config/database')

//middleware
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({extended : false}))

app.use(cors())
app.use(morgan("dev"))

app.use('/product', productRouter)
app.use('/order', orderRouter)

const PORT = process.env.PORT

app.listen(PORT, console.log("connected server..."))