const express = require('express')
const multer = require('multer')
const router = express.Router()
const keepAuth = require('../middleware/keep-auth')
const {
    products_get_all,
    products_get_product,
    products_post_product,
    products_patch_product,
    products_delete_all,
    products_delete_product
} = require('../controller/product')

const storage = multer.diskStorage(
    {
        destination : function (req, file, cb){
            cb(null, './uploads')
        },
        filename : function (req, file, cb){
            cb(null, file.originalname)
        }
    }
)

const fileFilter = (req, file, cb) => {

    if(file.mimetype === 'image/jpeg' || file.mimetype === 'image/png'){
        cb(null, true)
    }
    else{
        cb(null, false)
    }
}

const upload = multer({
    storage : storage,
    limit : {
        filesize : 1024 * 1024 * 5
    },
    fileFilter : fileFilter
})

// get products
router.get("/", products_get_all)

// detail product
router.get("/:productId", keepAuth, products_get_product)

// register product
router.post("/",keepAuth, upload.single('productImage'), products_post_product)

// update product
router.patch("/:productId",keepAuth, products_patch_product)

// detele products
router.delete("/",keepAuth, products_delete_all)

// detail delete product
router.delete("/:productId",keepAuth, products_delete_product)

module.exports = router