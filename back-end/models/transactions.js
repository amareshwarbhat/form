var mongoose = require('mongoose');

//Definfing the schema
module.exports = mongoose.model('Transaction', {
    userName: String,
    bookISBN: String,
    date: String,
    status: String
})
