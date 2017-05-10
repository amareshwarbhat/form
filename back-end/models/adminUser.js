var mongoose = require('mongoose');


//Definfing the schema
module.exports = mongoose.model('AdminUser', {
    userName: String,
    password: String,
    name: String,
    email: String,
    mobileNumber: String
})
