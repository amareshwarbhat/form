var mongoose = require('mongoose');


//Definfing the schema
module.exports = mongoose.model('Book', {
    bookName: String,
    bookISBN: String,
    author: String,
    bookStatus: String
})
