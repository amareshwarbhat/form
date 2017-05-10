var mongoose = require('mongoose');

//Definfing the schema
module.exports = mongoose.model('User', {
    userName: String,
    name: String,
    email: String,
    mobileNumber: String,
    myList:String
})

