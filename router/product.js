const express = require('express')
const productModel = require('../model/product')
const router = express.Router()

// get products
router.get("/", (req, res) => {

    productModel
        .find()
        .then(products => {
            res.json({
                msg : "get products",
                count : products.length,
                productInfo : products
            })
        })
        .catch(err => {
            res.status(500).json({
                msg : err.message
            })
        })
})

// detail product
router.get("/:productId", (req, res) => {

    const id = req.params.productId

    productModel
        .findById(id)
        .then(product => {
            res.json({
                msg :"get product",
                productInfo : product
            })
        })
        .catch(err => {
            res.status(500).json({
                msg : err.message
            })
        })
})

// register product
router.post("/", (req, res) =>{

    const newProduct = new productModel(
        {
            name : req.body.productName,
            price : req.body.productPrice
        }
    )

    newProduct
        .save()
        .then(product => {
            res.json({
                msg : "register product",
                productInfo : product
            })
        })
        .catch(err => {
            res.status(500).json({
                msg : err.message
            })
        })
})

// update product
router.patch("/:productId", (req, res) => {
    const id = req.params.productId

    const updateOps = {}

    for(const ops of req.body){
        updateOps[ops.propName] = ops.value
    }

    productModel
        .findByIdAndUpdate(id, {$set : updateOps})
        .then(() => {
            res.json({
                msg : "update product by " + id
            })
        })
        .catch(err => {
            res.status(500).json({
                msg : err.message
            })
        })
})

// detele products
router.delete("/", (req, res) => {

    productModel
        .remove()
        .then(() => {
            res.json({
                msg : "delete products"
            })
        })
        .catch(err => {
            res.status(500).json({
                msg : err.message
            })
        })
})

// detail delete product
router.delete("/:productId", (req, res) => {

    const id = req.params.productId
    productModel
        .findByIdAndRemove(id)
        .then(() => {
            res.json({
                msg : "delete product by " + id
            })
        })
        .catch(err => {
            res.status(500).json({
                msg : err.message
            })
        })
})

module.exports = router