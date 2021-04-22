const mongoose = require('mongoose')

const productSchema = mongoose.Schema(
    {
        name : String,
        price : Number
    },
    {
        timestamps : true
    }
)

module.exports = mongoose.model('product', productSchema)