const express = require('express')
const keepAuth = require('../middleware/keep-auth')

const {
    orders_get_all,
    orders_get_order,
    orders_post_order,
    orders_patch_order,
    orders_delete_all,
    orders_delete_order
} =require('../controller/order')
const router = express.Router()

// get order
router.get("/", keepAuth, orders_get_all)

// detail get order
router.get("/:orderId",keepAuth, orders_get_order)

// register order
router.post("/",keepAuth, orders_post_order)

// update order
router.patch("/:orderId",keepAuth, orders_patch_order)

// delete order
router.delete("/",keepAuth, orders_delete_all)

// detail delete order
router.delete("/:orderId",keepAuth, orders_delete_order)

module.exports = router