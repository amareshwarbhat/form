/*
 * Main routing fields
 */

//"start": "nodemon ./bin/www"
var bCrypt = require('bcrypt-nodejs');
var constants = require('../../constants');
var neo4j = require('neo4j-js');
var async = require('async');
var express = require('express');
var multiparty = require('multiparty');
var fs = require('fs');
var expressJwt = require('express-jwt');
var jwt = require('jsonwebtoken');
var router = express.Router();
var BASE_API_URL = "";
var config = require('./config');
var request = require('request');
var aws = require('aws-sdk');
var Zoho = require('node-zoho');
var nodemailer = require('nodemailer');
//var googl = require('goo.gl');//for short url

var utils = require('../../utils/utils');
var sendOTP = require('../../utils/sendOTP');

var version = constants.version;
var sangeetGuruApp = constants.sangeetGuruApp;
var guruSangeetSkyApp = constants.guruSangeetSkyApp;
var taalaJson = constants.taalaJson;
var ragaJson = constants.ragaJson;
var googlShortURLKey = constants.googlShortURLKey;
var apiKey = constants.opentokAPIKey;
var apiSecret = constants.opentokSecret;
var neo4JUrl = constants.neo4JUrl;
var zohoAuthKey = constants.zohoAuthKey;
var msangeetGoogleUserName = constants.msangeetGoogleUserName;
var msangeetGooglePassword = constants.msangeetGooglePassword;
var key = constants.msg91key;

var ignoreSendOTP = true;
var ignoreInviteSendSMS = false;
var ignoreLoginSendSMS = false;

var Client = require('node-rest-client').Client;
var client = new Client();

var OpenTok = require('opentok'),
    opentok = new OpenTok(apiKey, apiSecret);

zoho = new Zoho({ authToken: zohoAuthKey });

var transporter = nodemailer.createTransport("SMTP", {
    service: 'Gmail',
    auth: {
        user: msangeetGoogleUserName, // Your email id
        pass: msangeetGooglePassword // Your password
    }
});

var log4js = require('log4js');
log4js.configure({
    appenders: [
        { type: 'console' },
        { type: 'file', filename: 'mSangeetlog.log', category: 'mSangeetlog' },
    ]
});

var logger = log4js.getLogger('mSangeetlog');
logger.setLevel('DEBUG');

/*logger.setLevel('ERROR');
logger.trace('Entering debug testing');
logger.debug('Got debug.');
logger.info('debug is Gouda.');
logger.warn('debug is quite smelly.');
logger.error('debug is too ripe!');
logger.fatal('debug was breeding ground for listeria.');*/

var createHash = function (password) {
    return bCrypt.hashSync(password, bCrypt.genSaltSync(10), null);
}

var isValidPassword = function (password, passwordFilter) {
    return bCrypt.compareSync(password, passwordFilter);
}
var app = express();

var graph = null;
var neod = require('domain').create();


neod.run(function () {
    neo4j.connect(neo4JUrl, function (err, graph1) {
        if (err) {
            console.log("neo4j connection failed");
            logger.error('neo4j connection failed');
        } else {
            graph = graph1;
            console.log("successfully connected to neo4j");
            logger.info("successfully connected to neo4j");
        }
    });
});



var isNeo4jOn = function (req, res, next) {
    neod.run(function () {
        neo4j.connect(neo4JUrl, function (err, graph1) {
            if (err) {
                console.log("neo4j connection failed");
                logger.error('neo4j connection failed');

                res.json({
                    "statuscode": 203
                    , "msgkey": "DB_failure"
                    , "v": version
                });

            } else {
                graph = graph1;
                console.log("successfully connected to neo4j");
                logger.info("successfully connected to neo4j");
                next();
            }
        });
    });
}

var isAuthenticated = function (req, res, next) {
    console.log(req);
    if (req.isAuthenticated()) {
        console.log('user logged in', req.user);
        next();
    }
    // if the user is not authenticated then redirect him to the login page
    res.redirect(BASE_API_URL + '/');
}

var isAuthenticatedAccessToken = function (req, res, next) {
    var token = req.headers['x-access-token'];
    // decode token
    if (token) {
        // verifies secret and checks exp
        jwt.verify(token, "!@OlaHivemSangeet@!", function (err, decoded) {
            if (err) {
                return res.json({
                    success: false
                    , message: 'Failed to authenticate token.'
                });
            }
            else {
                // if everything is good, save to request for use in other routes
                req.user = decoded;
                console.log(decoded);
                next();
            }
        });
    }
    else {
        // if there is no token return an error
        return res.status(403).send({
            "statuscode": "203"
            , "msgkey": "api.access.token.failed"
            , "v": version
        });
    }
}

module.exports = function (passport) {

    router.get(BASE_API_URL + '/books', function (req, res) {

        console.log("inside get books api");
        var reponseJson = [{
            "bookId": 1,
            "name": "Harry Potter and The Prisoner of Azkaban",
            "price": "INR 700.00",
            "inStock": 52
        }, {
            "bookId": 2,
            "name": "Hamlet",
            "price": "INR 1700.00",
            "inStock": 47
        }];
        // res.render('/', { message: req.flash('message') });
        res.json(reponseJson);
    });

    router.post(BASE_API_URL + '/books', function (req, res) {
        console.log("inside books post method");
        var bookId = req.body.bookId;
        var name = req.body.name;
        var price = req.body.price;
        var inStock = req.body.inStock;

        var responseJson = {
            "bookId": bookId,
            "name": name,
            "price": price,
            "inStock": inStock
        };

        res.json(responseJson);

    });

    router.get(BASE_API_URL + "/books/:bookId", function (req, res) {
        console.log("insite books get method with param");
        var bookId = req.params['bookId'];
        console.log("param bookId: " + bookId);

        var reponseJson;

        if (bookId == 1) {
            responseJson = {
                "bookId": 1,
                "name": "Harry Potter and The Prisoner of Azkaban",
                "price": "INR 700.00",
                "inStock": 52
            };
        }
        else if (bookId == 2) {
            responseJson = {
                "bookId": 2,
                "name": "Hamlet",
                "price": "INR 1700.00",
                "inStock": 47
            };
        }

        res.json(responseJson);
    });

    //OpenTalk session create
    router.post(BASE_API_URL + '/opentokSessionIdTest', function (req, res) {

        var mediaMode = req.body.mediaMode;

        console.log("req.body");
        console.log(req.body);

        opentok.createSession({ mediaMode: mediaMode }, function (err, session) {
            if (err) {
                var data = {
                    "statuscode": 206
                    , "msgkey": "sessionId_does_not_created"
                    , "v": version
                }; callback(data);
                return console.log(err);
            }
            var OTSessionId = session.sessionId;

            res.json({
                "statuscode": 200
                , "msgkey": "OTSessionID generated successful"
                , "OTSessionId": OTSessionId
                , "v": version
            });

        });

    });

    //OpenTalk generate tokens starts 
    router.post(BASE_API_URL + '/opentokTokenTest', function (req, res) {

        var sessionId = req.body.sessionId;
        var role = req.body.role;
        var expireTime = req.body.expireTime;
        console.log("req.body");
        console.log(req.body);

        if (expireTime == '1 day') {
            days = 1;
            hour = 24;
            min = 60;
            sec = 60;
        }

        else if (expireTime == '1 week') {
            days = 7;
            hour = 24;
            min = 60;
            sec = 60;

        } else if (expireTime == '1 hour') {
            days = 1;
            hour = 1;
            min = 60;
            sec = 60;
        } else if (expireTime == '1 month') {
            days = 30;
            hour = 24;
            min = 60;
            sec = 60;
        }
        else {
            res.json({
                "statuscode": "400"
                , "msgkey": "pls choose atleast 1 time"
                , "v": version
            });
        }

        //else pls enter some time

        token = opentok.generateToken(sessionId, {
            role: role,
            expireTime: (new Date().getTime() / 1000) + (days * hour * min * sec)
        });

        var reponseJson = {
            "statuscode": "210"
            , "token": token
            , "v": version
        };
        res.json(reponseJson);

    });


    router.post(BASE_API_URL + '/testone', function (req, res) {
        neo4j.connect(neo4JUrl, function (err, graph) {
            if (err) {
                res.json({
                    "statuscode": "203"
                    , "msgkey": "dbconnection.failure"
                    , "v": version
                });
            }
            else {
                var data = {
                    "countryCode": "91",
                    "mobileNumber": "7829657293"
                };
                sendOTP.sendOTPCall(data, function (sendOTPCallResults) {
                    res.json({
                        "status": sendOTPCallResults.status,
                        "statuscode": sendOTPCallResults.statuscode,
                        "msgkey": sendOTPCallResults.msgkey,
                        "isVerificationNeeded": sendOTPCallResults.isVerificationNeeded,
                        "v": sendOTPCallResults.v
                    });
                });

                /*var query;
                query = ["MATCH (n:mUser) WHERE n.countryCode=91 RETURN n.uuid"].join('\n');
                graph.query(query, function (err, results) {
                    console.log(results);

                    //Way to send json resposes json object array
                    if (results.length) {
                        res.json({
                            "statuscode": "204"
                            , "msgkey": "update failed lastOTPVarificationDate"
                            , "data": results
                            , "v": version
                        });

                    }
                    else {
                        console.log("else part");
                    }
                });*/
            }
        });
    });




    /**
   * @api {get} /users Get Version
   * @apiVersion 0.3.0
   * @apiName GetVersion
   * @apiGroup Version
   * @apiPermission none
   *
   * @apiDescription  This API is will give the versions
   * 
   * @apiParam {secToken} String Users Security Token
   * 
   * @apiSuccess {int} statuscode  Status Code
   * @apiSuccess {String} msgkey Message Key
   * @apiSuccess {String} sangeetGuruApp SangeetGuruApp version
   * @apiSuccess {String} guruSangeetSkyApp GuruSangeetSkyApp version
   * @apiSuccess {String} taalaJson TaalaJson version
   * @apiSuccess {String} ragaJson RagaJson version
   * @apiSuccess {String} v version
   *
   * @apiSuccessExample Success-Response:
   *     HTTP/1.1 200 OK
   *     {
   *       "statuscode": 200,
   *       "msgkey": "your version is 1.0",
   *       "sangeetGuruApp": sangeetGuruApp,
   *       "guruSangeetSkyApp": guruSangeetSkyApp,
   *       "taalaJson": taalaJson,
   *       "ragaJson": ragaJson,
   *       "v": version
   *     }
   * 
   * @apiError Error in Database
   *
   * @apiErrorExample Error-Response:
   *     HTTP/1.1 404 Not Found
   * 
   */

    //GET /Version
    // This API is will give the versions
    // Return the versions of the sangeetGuruApp, guruSangeetSkyApp, taalaJson, ragaJson
    router.get(BASE_API_URL + '/version', function (req, res) {
        logger.info("Inside version [POST]");
        res.json({
            "statuscode": 200
            , "msgkey": "your version is " + version
            , "sangeetGuruApp": sangeetGuruApp
            , "guruSangeetSkyApp": guruSangeetSkyApp
            , "taalaJson": taalaJson
            , "ragaJson": ragaJson
            , "v": version
        });
    });


    /**
 * @api {post} /users Create User node
 * @apiVersion 0.3.0
 * @apiName PostUser
 * @apiGroup Users
 * @apiPermission none
 *
 * @apiDescription  This API is invoked to create a new mUser.
 * If the user already exists, then nothing is done
 * 
 * @apiParam {countryCode} int Users countryCode
 * @apiParam {mobileNumber} String Users mobileNumber
 * @apiParam {isGuru} Boolean Users role
 * @apiParam {isShishya} Boolean Users role
 * 
 * @apiSuccess {int} statuscode  Status Code
 * @apiSuccess {String} msgkey Message Key
 * @apiSuccess {String} uuid uuid of the User
 * @apiSuccess {Boolean} isMobileNumberVerified Users Mobile Number varified or not
 * @apiSuccess {String} v version
 *
 * @apiSuccessExample Success-Response:
 *     HTTP/1.1 200 OK
 *     {
 *       "statuscode": 200,
 *       "msgkey": "user_already_exist",
 *       "uuid": "c89f0220ae6611e68bb33a84bb3e39cf",
 *       "isMobileNumberVerified": false,
 *       "v": "1.0"
 *     }
 * 
 *    {
 *       "statuscode": 200,
 *       "msgkey": "user_already_exist",
 *       "uuid": "c89f0220ae6611e68bb33a84bb3e39cf",
 *       "isMobileNumberVerified": true,
 *       "v": "1.0"
 *     }
 * 
 * 
 * @apiError Error in Database
 *
 * @apiErrorExample Error-Response:
 *     HTTP/1.1 404 Not Found
 *     {
 *        "statuscode": 203,
 *        "msgkey": "DB_failure",
 *        "v": version
 *     }
 */

    // POST /users
    // This API is invoked to create a new mUser.
    // If the user already exists, then nothing is done
    // Return the basic details of the user below
    router.post(BASE_API_URL + '/users', isNeo4jOn, function (req, res) {
        logger.info("Inside Users [POST]");
        console.log("graph"); console.log(graph);

        //Step 0: Local Variable Declarations
        var query, uuid, isMobileNumberVerified, userData, props;

        //Step 1: Parse Request Parameters
        var countryCode = req.body.countryCode;
        var mobileNumber = req.body.mobileNumber;
        var isGuru = req.body.isGuru;
        var isShishya = req.body.isShishya;

        logger.debug("req.body"); logger.debug(req.body);

        //Step 2: Check if the user already exists
        query = ["MATCH (n:mUser) WHERE n.countryCode = " + countryCode + " "
            + "AND n.mobileNumber = '" + mobileNumber + "' "
            + "RETURN n.isMobileNumberVerified, n.uuid"].join('\n');
        logger.debug("query: Check if the user already exists"); logger.debug(query);

        //if(graph!=null){ excecute the below code  graph.query(query, function (err, results) else send error respo 203}
        graph.query(query, function (err, results) {

            if (err) {
                logger.error("error: "); logger.error(err);
                logger.info("Query failed");
                /* res.json({
                     "statuscode": 203
                     , "msgkey": "DB_failure"
                     , "v": version
                 });*/
            }

            if (results.length) {
                logger.info("User found");
                logger.debug("results: "); logger.debug(results);
                res.json({
                    "statuscode": 200
                    , "msgkey": "user_already_exist"
                    , "uuid": results[0]["n.uuid"]
                    , "isMobileNumberVerified": results[0]["n.isMobileNumberVerified"]
                    , "v": version
                });

            }
            //Step 4: User does not exist. Create new node and return user data
            else {
                logger.info("User does not exist");

                props = { "countryCode": parseInt(countryCode), "mobileNumber": mobileNumber, isMobileNumberVerified: false };
                logger.debug("props"); logger.debug(props);

                if (isGuru == true) {
                    logger.info("guru=true");

                    props["isGuru"] = true;
                    props["isGuruApproved"] = false;
                }
                else if (isShishya == true) {
                    logger.info("isShishya=true");

                    props["isShishya"] = true;
                    props["isShishyaApproved"] = false;
                }
                var parameters = {
                    "props": props
                };

                logger.debug("parameters"); logger.debug(parameters);

                query = "CREATE (n:mUser { props }) RETURN n.uuid";
                logger.debug("query: Create new user"); logger.debug(query);

                graph.query(query, parameters, function (err, results) {

                    if (err) {
                        logger.error("error: "); logger.error(err);
                        logger.info("Query failed");

                        res.json({
                            "statuscode": 203
                            , "msgkey": "DB_failure"
                            , "v": version
                        });
                    }

                    if (results.length) {
                        logger.info("New user created");
                        logger.debug("New user details results: "); logger.debug(results);

                        //retrieve the uuid of the newly created user
                        query = ["MATCH (n:mUser) WHERE n.countryCode = " + countryCode + " "
                            + "AND n.mobileNumber = '" + mobileNumber + "' "
                            + "RETURN n.uuid,n.isMobileNumberVerified"].join('\n');

                        logger.debug("query: To retrieve the uuid of the newly created user"); logger.debug(query);

                        graph.query(query, function (err, results) {
                            if (err) {
                                logger.error("error: "); logger.error(err);
                                logger.info("Query failed");

                                //say error
                                /* res.json({
                                     "statuscode": 200
                                     , "msgkey": "query_failure"
                                     , "v": version
                                 });*/
                            }

                            if (results.length) {
                                logger.debug("New user details results: "); logger.debug(results);
                                logger.info("New user details retrived");

                                /*   uuid = results[0]["n.uuid"];
                                   isMobileNumberVerified = results[0]["n.isMobileNumberVerified"];*/

                                res.json({
                                    "statuscode": 200
                                    , "msgkey": "new_user_created"
                                    , "uuid": results[0]["n.uuid"]
                                    , "isMobileNumberVerified": results[0]["n.isMobileNumberVerified"]
                                    , "v": version
                                });
                            }

                        }); //end: graph.query(query, function (err, results) {

                    } else { //database error
                        logger.info("New user not created");
                        logger.fatal("DB_failure");
                        res.json({
                            "statuscode": 203
                            , "msgkey": "DB_failure"
                            , "v": version
                        });

                    } //end: if (restults.length) {

                }); //end: graph.query(query, parameters, function (err, results) {

            } //end: if (results.length) { //User exists... return the user details

        }); //end: graph.query(query, function (err, results) {

    }); //end: router.post(BASE_API_URL + '/users', function (req, res) {


    /**
 * @api {post} /otp send OTP
 * @apiVersion 0.3.0
 * @apiName PostOTP
 * @apiGroup OTP
 * @apiPermission none
 *
 * @apiDescription This API is invoked whenever a new OTP needs to be generated for a user.
 * 
 * @apiParam {countryCode} int Users countryCode
 * @apiParam {mobileNumber} String Users mobileNumber
 *
 * @apiSuccess {int} statuscode  Status Code
 * @apiSuccess {String} status Status
 * @apiSuccess {String} msgkey Message Key
 * @apiSuccess {String} v version
 *
 * @apiSuccessExample Success-Response:
 *     HTTP/1.1 200 OK
 *     {
 *       "statuscode": 200,
 *       "status": "success",
 *       "msgkey": "OTP_SENT_SUCCESSFULLY",
 *       "v": "1.0"
 *     }
 *
 * @apiError Error in input.
 *
 * @apiErrorExample Error-Response:
 *     HTTP/1.1 404 Not Found
 *     {
 *        "statuscode": 400,
 *        "status": "error",
 *        "msgkey": "INVALID_MOBILE_NUMBER , MOBILE_NUMBER_LENGTH_MUST_BE_BETWEEN_7_AND_20",
 *        "v": version
 *     }
 */
    // POST /otp
    // This API is invoked whenever a new OTP needs to be generated for a user.
    router.post(BASE_API_URL + '/otp_Without_Functions', function (req, res) {
        logger.info("Inside otp [POST]");

        //Step 0: Local Variable Declarations
        var countryCodeString;

        //Step 1: Parse Request Parameters
        var countryCode = req.body.countryCode;
        var mobileNumber = req.body.mobileNumber;
        logger.debug("req.body"); logger.debug(req.body);
        //Step 2: Send OTP via msg91SendOTP
        var Url = 'https://sendotp.msg91.com/api/generateOTP';
        //var key = '5L1m4A4Z-rksuOruFJDSTv0Kc14LqPMv-DfKNxyDGbgmr-88uDKDTOpvJsSFyJzy66cS-E3cQnTobyg7TW7Ef40C4LGIhByoeyMdEGETR3lfQPwSHp4HqzlabTtSiYyd9KJCwJ5FMK4LlyBSAFbg1w==';

        countryCodeString = countryCode.toString();
        var reqData = { countryCode: countryCodeString, mobileNumber: mobileNumber, getGeneratedOTP: true };
        logger.debug("Url " + Url);
        logger.debug("reqData send to sendOTP- "); logger.debug(reqData);
        var args = {
            data: reqData,
            headers: { "Content-Type": "application/json", "application-Key": key }
        };
        logger.debug("args sending to sendOTP"); logger.debug(args);

        if (ignoreSendOTP == false) {
            logger.info("OTP sending");
            client.post(Url, args, function (response) {
                if (response.status == "error") {
                    logger.info("OTP failed");
                    res.json({
                        "statuscode": 400
                        , "status": response.status
                        , "msgkey": response.response.code
                        , "v": version
                    });
                }
                else { //if response.status == 'success'
                    logger.info("OTP success");
                    res.json({
                        "statuscode": 200
                        , "status": response.status
                        , "msgkey": response.response.code
                        , "v": version
                    });
                }
            });
        } else {
            logger.info("OTP ignored");
            res.json({
                "statuscode": 200
                , "status": "success"
                , "msgkey": "OTP_SENT_SUCCESSFULLY_DUMMY"
                , "v": version
            });
        }



    }); //end: router.post(BASE_API_URL + '/otp', function (req, res) {


    router.post(BASE_API_URL + '/otp', function (req, res) {
        logger.info("Inside otp [POST]");

        //Step 0: Local Variable Declarations
        var countryCodeString, data;

        //Step 1: Parse Request Parameters
        var countryCode = req.body.countryCode;
        var mobileNumber = req.body.mobileNumber;
        logger.debug("req.body"); logger.debug(req.body);

        data = {
            "countryCode": countryCode,
            "mobileNumber": mobileNumber
        };
        sendOTP.sendOTPCall(data, function (sendOTPCallResults) {
            res.json(
                sendOTPCallResults
            );
        });

    }); //end: router.post(BASE_API_URL + '/otp', function (req, res) {




    /**
 * @api {put} /otp validate OTP
 * @apiVersion 0.3.0
 * @apiName PutOTP
 * @apiGroup OTP
 * @apiPermission none
 *
 * @apiDescription This API verifies OTP sent by the user.
 * This API is invoked whenever the client needs to validate the OTP
 * entered by the user
 * 
 * @apiParam {countryCode} int Users countryCode
 * @apiParam {mobileNumber} String Users mobileNumber
 * @apiParam {oneTimePassword} String Users OTP
 *
 * @apiSuccess {int} statuscode  Status Code
 * @apiSuccess {String} status Status
 * @apiSuccess {String} msgkey Message Key
 * @apiSuccess {String} v version
 *
 * @apiSuccessExample Success-Response:
 *     HTTP/1.1 200 OK
 *     {
 *       "statuscode": 200,
 *       "status": "success",
 *       "msgkey": "NUMBER_VERIFIED_SUCCESSFULLY",
 *       "v": "1.0"
 *     }
 *
 * @apiError Error in input.
 *
 * @apiErrorExample Error-Response:
 *     HTTP/1.1 404 Not Found
 *     {
 *        "statuscode": 400,
 *        "status": "error",
 *        "msgkey": "OTP_INVALID",
 *        "v": version
 *     }
 */
    // PUT /otp
    // This API is invoked whenever the client needs to validate the OTP
    // entered by the user.
    router.put(BASE_API_URL + '/otp', function (req, res) {
        logger.info("Inside otp [PUT]");

        //Step 0: Local Variable Declarations
        var query, countryCodeString;

        //Step 1: Parse Request Parameters
        var countryCode = req.body.countryCode;
        var mobileNumber = req.body.mobileNumber;
        var oneTimePassword = req.body.oneTimePassword;

        logger.debug("req.body"); logger.debug(req.body);

        var date = new Date();
        var day = date.getDate();
        var month = (date.getMonth() + 1);
        var year = date.getFullYear();
        var hour = date.getHours();
        var min = date.getMinutes();
        var sec = date.getSeconds();
        var milliSec = date.getMilliseconds();
        var todaysDate = year * Math.pow(10, 13) + month * Math.pow(10, 11) + day * Math.pow(10, 9) + hour * Math.pow(10, 7) + min * Math.pow(10, 5) + sec * Math.pow(10, 3) + milliSec;

        logger.debug("todaysDate: " + todaysDate);

        //Step 2: Invoke MSG91 verifyOTP method to validate user entered OTP
        var Url = 'https://sendotp.msg91.com/api/verifyOTP';

        countryCodeString = countryCode.toString();
        var reqData = { countryCode: countryCodeString, mobileNumber: mobileNumber, oneTimePassword: oneTimePassword };

        logger.debug("Url " + Url);
        logger.debug("reqData"); logger.debug(reqData);

        var args = {
            data: reqData,
            headers: { "Content-Type": "application/json", "application-Key": key }
        };

        logger.debug("args"); logger.debug(args);

        if (ignoreSendOTP == false) {
            logger.info("otp verifying");

            client.post(Url, args, function (response) {

                if (response.status == "error") {
                    res.json({
                        "statuscode": 400
                        , "status": response.status
                        , "msgkey": response.response.code
                        , "v": version
                    });
                }
                else { //if response.status == 'success'
                    logger.info("Verified success");

                    //Step 3: Update DB to set isMobileNumberVerified = true
                    query = ["MATCH (n:mUser) WHERE n.countryCode = " + countryCode + " "
                        + "AND n.mobileNumber = '" + mobileNumber + "' "
                        + " SET n.isMobileNumberVerified = true, n.lastOTPVarificationDate=" + todaysDate + " "
                        + " RETURN n"].join('\n');

                    logger.debug("query: To update DB as isMobileNumberVerified = true"); logger.debug(query);

                    graph.query(query, function (err, results) {
                        logger.debug("results: DB Updatd with isMobileNumberVerified = true"); logger.debug(results);

                    });//end: graph.query(query, function (err, results) {

                    res.json({
                        "statuscode": 200
                        , "status": response.status
                        , "msgkey": response.response.code
                        , "v": version
                    });

                }//end:if response.status == 'success'
            }); //end: client.post(Url, args, function (response) {
        }//dummy
        else {
            logger.info("OTP ignored");

            query = ["MATCH (n:mUser) WHERE n.countryCode = " + countryCode + " "
                + "AND n.mobileNumber = '" + mobileNumber + "' "
                + " SET n.isMobileNumberVerified = true RETURN n"].join('\n');

            logger.debug("query: To update DB as isMobileNumberVerified = true"); logger.debug(query);

            graph.query(query, function (err, results) {
                logger.info("Verified success");
                logger.debug("results"); logger.debug(results);
            });

            res.json({
                "statuscode": 200
                , "status": "success"
                , "msgkey": "NUMBER_VERIFIED_SUCCESSFULLY_OTP_Ignored"
                , "v": version
            });
        }
    }); //end: router.put(BASE_API_URL + '/otp', function (req, res) {


    /**
 * @api {post} /users/:id/secToken Gives Security Token
 * @apiVersion 0.3.0
 * @apiName PostSecToken
 * @apiGroup Users
 * @apiPermission none
 *
 * @apiDescription This API is invoked whenever a new OTP needs to be generated for a user.
 * This API is invoked each time upon login to obtain the jwt security token
 * 
 * @apiParam {id} String Users uuid
 * 
 * @apiSuccess {int} statuscode  Status Code
 * @apiSuccess {String} msgkey Message Key
 * @apiSuccess {token} token Token
 * @apiSuccess {uuid} uuid uuid
 * @apiSuccess {String} v version
 *
 * @apiSuccessExample Success-Response:
 *     HTTP/1.1 200 OK
 *     {
 *       "statuscode": 200,
 *       "msgkey": "login_success",
 *       "token": "eyJhbGciOiJIUzI1NiJ9.N2MzYWIyMzBhZmUyMTFlNmI0M2MxMjdiYTI1Y2ViNmQ.eo4hpwzVMa-0U3lJKv0_NRQXPa2J50bjU1ryws7NcXs",
 *       "uuid": "7c3ab230afe211e6b43c127ba25ceb6d",    
 *       "v": "1.0"
 *     }
 *
 * @apiError Error in input.
 * 
 * @apiErrorExample Error-Response:
 *     HTTP/1.1 404 Not Found
 *     {
 *        "statuscode": 400,
 *        "status": "error",
 *        "msgkey": "user_does_not_exist",
 *        "v": version
 *     }
 */

    // This API is invoked whenever a new OTP needs to be generated for a user.
    // POST /secToken
    // This API is invoked each time upon login to obtain the jwt security token
    router.post(BASE_API_URL + '/users/:id/secToken', function (req, res) {
        logger.info("Inside secToken [POST]");
        //Step 0: Local Variable Declarations
        var query, token;

        //Step 1: Parse Request Parameters
        var uuid = req.params['id'];
        logger.debug("req.params: "); logger.debug(req.params);

        query = ["MATCH (n:mUser) WHERE n.uuid = '" + uuid + "' "
            + "RETURN n.isMobileNumberVerified, n.uuid"].join('\n');

        logger.debug("query: Match the mUser reocrd to retrieve uuid and isMObileNumberVerified: "); logger.debug(query);

        graph.query(query, function (err, results) {
            if (err) {
                logger.debug("err: "); logger.debug(err);
                logger.info("Query failed");
                res.json({
                    "statuscode": 400
                    , "status": "error"
                    , "msgkey": "user_does_not_exist"
                    , "v": version
                });
            }

            //Step 3: If User exists... return the user details
            if (results.length) {
                logger.debug("results: "); logger.debug(results);
                logger.info("User exists & user details retrieved success");
                if (results[0]["n.isMobileNumberVerified"] == false) {
                    logger.info("MobileNumber not Verified ");

                    res.json({
                        "statuscode": 400
                        , "status": "error"
                        , "msgkey": "user_not_verfied"
                        , "v": version
                    });
                }//end results[0]["n.isMobileNumberVerified"] == false
                else { //user is verified user
                    token = jwt.sign({ user: uuid }, "!@OlaHivemSangeet@!", { expiresIn: '24h' });
                    res.json({
                        "statuscode": 200
                        , "msgkey": "login_success"
                        , "token": token
                        , "uuid": uuid
                        , "v": version
                    });
                }//end user is verified user
            }//end: if (results.length) { //User exists... return the user details
            else {//User does not exist
                logger.info("User does not exist ");
                res.json({
                    "statuscode": 400
                    , "status": "error"
                    , "msgkey": "user_does_not_exist"
                    , "v": version
                });
            } //end :User does not exist
        }); //end: graph.query(query, function (err, results) {
    }); //router.put(BASE_API_URL + '/secToken', function (req, res) {


    /**
 * @api {get} /users/:id/basicProfile Get the Users basic profile details
 * @apiVersion 0.3.0
 * @apiName getbasicProfile
 * @apiGroup Users
 * @apiPermission none
 *
 * @apiDescription This API gives firstName, lastName.
 * 
 * @apiParam {uuid} String Users uuid
 * @apiParam {secToken} String Users secToken
 * 
 * @apiSuccess {int} statuscode  Status Code
 * @apiSuccess {String} msgkey Message Key
 * @apiSuccess {String} firstName First Name of the User
 * @apiSuccess {String} lastName Users Last Name of the User
 * @apiSuccess {String} v version
 *
 * @apiSuccessExample Success-Response:
 *     HTTP/1.1 200 OK
 *     {
 *       "statuscode": 200,
 *       "msgkey": "basicProfile_success",
 *       "firstName": "Amar",
 *       "lastName": "Bhat",
 *       "v": "1.0"
 *     }
 *
 * @apiError Error in Database
 *
 * @apiErrorExample Error-Response:
 *     HTTP/1.1 404 Not Found
 *     {
 *        "statuscode": 400,
 *        "msgkey": "basicProfile_failure",
 *        "firstName": null,
 *        "lastName": null,
 *        "v": version
 *     }
 */

    // GET /users/id={uuid}/basicProfile
    // This API gives firstName, lastName
    router.get(BASE_API_URL + '/users/:id/basicProfile', function (req, res) {
        logger.info("Inside basicProfile [GET]");

        //Step 0: Local Variable Declarations
        var query, isGuruApproved, isShishyaApproved, isBasicProfileSet;
        //Step 1: Parse Request Parameters

        var uuid = req.params['id'];
        logger.debug("req.params: "); logger.debug(req.params);

        query = ["MATCH (n:mUser) WHERE n.uuid = '" + uuid + "' "
            + "RETURN n.firstName, n.lastName, n.isGuruApproved, n.isShishyaApproved, n.isBasicProfileSet "].join('\n');
        logger.debug("query: Retrieving the Basic profile of user: "); logger.debug(query);

        graph.query(query, function (err, results) {
            if (err) {
                logger.error("error: "); logger.error(err);
                logger.info("Query failed");

                res.json({
                    "statuscode": 400
                    , "msgkey": "basicProfile_failure"
                    , "firstName": null
                    , "lastName": null
                    , "isGuruApproved": null
                    , "isShishyaApproved": null
                    , "isBasicProfileSet": null
                    , "v": version
                });
            }

            if (results.length) {
                logger.info("Basic profile details retrieved successful ");
                logger.debug("results: "); logger.debug(results);

                isGuruApproved = results[0]["n.isGuruApproved"];
                isShishyaApproved = results[0]["n.isShishyaApproved"];
                isBasicProfileSet = results[0]["n.isBasicProfileSet"];

                if (isGuruApproved == null) {
                    isGuruApproved = false;
                }

                if (isShishyaApproved == null) {
                    isShishyaApproved = false;
                }

                if (isBasicProfileSet == null) {
                    isBasicProfileSet = false;
                }

                res.json({
                    "statuscode": 200
                    , "msgkey": "basicProfile_success"
                    , "firstName": results[0]["n.firstName"]
                    , "lastName": results[0]["n.lastName"]
                    , "isGuruApproved": isGuruApproved
                    , "isShishyaApproved": isShishyaApproved
                    , "isBasicProfileSet": isBasicProfileSet
                    , "v": version
                });

            }//end: if (results.length) { //User exists... return the user details
            else {
                logger.info("Basic profile details retrieved failed ");
                res.json({
                    "statuscode": 400
                    , "msgkey": "basicProfile_failure"
                    , "firstName": null
                    , "lastName": null
                    , "isGuruApproved": null
                    , "isShishyaApproved": null
                    , "isBasicProfileSet": null
                    , "v": version
                });

            } //end :BasicProfile details failure
        }); //end: graph.query(query, function (err, results) {

    });


    /**
 * @api {put} /users/:id/basicProfile Update the Users basic profile details
 * @apiVersion 0.3.0
 * @apiName putBasicProfile
 * @apiGroup Users
 * @apiPermission none
 *
 * @apiDescription This API Sets the firstName, lastName.
 * 
 * @apiParam {uuid} String Users uuid
 * @apiParam {secToken} String Users secToken
 * @apiParam {firstName} String Users First Name
 * @apiParam {lastName} String Users Last Name
 * 
 * @apiSuccess {int} statuscode  Status Code
 * @apiSuccess {String} msgkey Message Key
 * @apiSuccess {String} v version
 *
 * @apiSuccessExample Success-Response:
 *     HTTP/1.1 200 OK
 *     {
 *       "statuscode": 200,
 *       "msgkey": "basicProfile_details_updated_success",
 *       "v": "1.0"
 *     }
 *
 * @apiError Error in Database
 *
 * @apiErrorExample Error-Response:
 *     HTTP/1.1 404 Not Found
 *     {
 *        "statuscode": 400,
 *        "msgkey": "basicProfile_details_update_failure",
 *        "v": version
 *     }
 */
    router.put(BASE_API_URL + '/users/:id/basicProfile', function (req, res) {
        logger.info("Inside basicProfile [PUT]");

        //Step 0: Local Variable Declarations
        var query;
        //Step 1: Parse Request Parameters

        var uuid = req.params['id'];
        var firstName = req.body.firstName;
        var lastName = req.body.lastName;

        logger.debug("req.params: "); logger.debug(req.params);
        logger.debug("req.body: "); logger.debug(req.body);

        query = ["MATCH (n:mUser) WHERE n.uuid = '" + uuid + "' "
            + "SET n.firstName='" + firstName + "' ,n.lastName='" + lastName + "', n.isBasicProfileSet =true RETURN n.firstName, n.lastName"].join('\n');

        logger.debug("query: update the Basic profile of user: "); logger.debug(query);

        graph.query(query, function (err, results) {

            if (err) {
                logger.error("error: "); logger.error(err);
                logger.info("Query failed");

                res.json({
                    "statuscode": 400
                    , "msgkey": "basicProfile_details_update_failure"
                    , "v": version
                });
            }
            if (results.length) {
                logger.debug("results: "); logger.debug(results);
                logger.info("Basic Profile details updated_success ");
                res.json({
                    "statuscode": 200
                    , "msgkey": "basicProfile_details_updated_success"
                    , "v": version
                });

            } //end: if (results.length) { //User exists... return the user details
            else {

                res.json({
                    "statuscode": 400
                    , "msgkey": "basicProfile_details_update_failure"
                    , "v": version
                });

            } //end :BasicProfile details failure
        }); //end: graph.query(query, function (err, results) {
    });


    /**
 * @api {get} /users/:id/otCredentials Get the Users otCredentials
 * @apiVersion 0.3.0
 * @apiName getotCredentials
 * @apiGroup otCredentials
 * @apiPermission none
 *
 * @apiDescription This API is called to retrive the OpenTok credentails of a specified user
 * Such as OTSessionId, OTToken
 * 
 * @apiParam {id} String Users uuid
 * @apiParam {secToken} String Users secToken
 * @apiParam {isGuru} Boolean Users Role
 * @apiParam {isShishya} Boolean Users Role
 * 
 * @apiSuccess {int} statuscode  Status Code
 * @apiSuccess {String} msgkey Message Key
 * @apiGroup otCredentials
 * @apiPermission none
 *
 * @apiDescription This API is called to retrive the OpenTok credentails of a specified user
 * Such as OTSessionId, OTToken
 * @apiSuccess {String[]} gurus Gurus Array
 * @apiSuccess {String} v version
 *
 * @apiSuccessExample Success-Response:
 *
 *   HTTP/1.1 200 OK
 *    {
 *     "statuscode": 200,
 *     "status": "success",
 *     "msgkey": "get_guru_success",
 *     "gurus": [
 *       {
 *         "status": "0",
 *         "firstName": null,
 *         "lastName": null,
 *         "uuid": "afb621b0b07511e6b0e986312c27d6db"
 *       },
 *       {
 *         "status": "0",
 *         "firstName": null,
 *         "lastName": null,
 *         "uuid": "dcee5a20b07111e6b0e986312c27d6db"
 *       }
 *     ],
 *    "v": "1.0"
 *    }
 * 
 * @apiError data not found in Database
 * 
 * @apiErrorExample Error-Response:
 *     HTTP/1.1 404 Not Found
 *     {
 *        "statuscode": 200,
 *        "msgkey": "otCredentials_retrieved_successfull",
 *        "gurus": null,
 *        "v": version
 *     }
 */


    //GET /users/id/otCredentials
    //This api is called to retrive the OpenTok credentails of a specified user
    // This api will implement separate logic for Gurus and Shishyas
    router.get(BASE_API_URL + '/users/:id/otCredentials', function (req, res) {
        logger.info("Inside otCredentials [GET]");

        //Step 0: declare local variables
        var query;

        //Step 1: Parse request paramenters
        var uuid = req.params['id'];
        var isGuru = req.query['isGuru'];
        var isShishya = req.query['isShishya'];

        logger.debug("req.params: "); logger.debug(req.params);
        logger.debug("req.query: "); logger.debug(req.query);

        if (uuid == null || (isGuru == null && isShishya == null)) {
            res.json({
                "statuscode": 200
                , "msgkey": "Please enter proper UUID/Role"
                , "v": version
            });
        }


        if (isGuru == "true") {
            logger.info("isGuru true");

            query = ["MATCH (g:mUser) WHERE g.uuid = '" + uuid + "' "
                + " AND g.OTSessionId IS NOT NULL RETURN g.OTSessionId"].join('\n');

            logger.debug("query: Check if the mUser node for Shishya exists: "); logger.debug(query);
            graph.query(query, function (err, results) {
                if (err) {
                    logger.error("error: "); logger.error(err);
                    logger.info("Query failed");
                    /* res.json({
                         "statuscode": 400
                         , "msgkey": "wrong_input"
                         , "v": version
                     });*/
                }

                if (results.length) {
                    logger.info("OTSessionId is present in database: ");
                    logger.debug("results: "); logger.debug(results);

                    var OTSessionId = results[0]["g.OTSessionId"];
                    //create OTToken and send otCredentials as response
                    var OTToken = opentok.generateToken(OTSessionId, {
                        role: "moderator",
                        expireTime: (new Date().getTime() / 1000) + (1 * 24 * 60 * 60)
                    });

                    logger.debug("OTToken created by database value------------  " + OTToken);
                    res.json({
                        "statuscode": 200
                        , "msgkey": "otCredentials_created_successfull which are from database"
                        , "OTSessionId": OTSessionId
                        , "OTToken": OTToken
                        , "v": version
                    });

                } //end: if (results.length) { //OTSessionId doesnot exist for this guru
                else {
                    logger.info("OTSessionId is null: ");
                    opentok.createSession({ mediaMode: "relayed" }, function (err, session) {
                        if (err) {
                            var data = {
                                "statuscode": 206
                                , "msgkey": "sessionId_does_not_created"
                                , "v": version
                            }; callback(data);
                            return console.log(err);
                        }

                        var OTSessionId = session.sessionId;
                        logger.debug("OTSessionId just created --------------" + OTSessionId);

                        query = ["MATCH (n:mUser) WHERE n.uuid = '" + uuid + "' "
                            + "SET n.OTSessionId='" + OTSessionId + "' RETURN n.OTSessionId"].join('\n');
                        logger.debug("query: setting OTSessionId for Guru: "); logger.debug(query);

                        graph.query(query, function (err, results) {
                            if (err) {
                                logger.debug("err: "); logger.debug(err);
                            }
                            if (results.length) {
                                logger.info("OTSessionId stored successful ");
                                logger.debug("results: "); logger.debug(results);
                            }
                        });

                        //create OTToken and send otCredentials as response
                        var OTToken = opentok.generateToken(OTSessionId, {
                            role: "moderator",
                            expireTime: (new Date().getTime() / 1000) + (1 * 24 * 60 * 60)
                        });

                        logger.debug("OTToken created by newly created session ID  " + OTToken);

                        res.json({
                            "statuscode": 200
                            , "msgkey": "otCredentials_created_successfull newly created session ID"
                            , "OTSessionId": OTSessionId
                            , "OTToken": OTToken
                            , "v": version
                        });
                    });
                }
            }); //end: graph.query(query, function (err, results) {

        }
        else if (isShishya == "true") {
            logger.info("isShishya true ");
            query = ["MATCH (s:mUser) WHERE s.uuid = '" + uuid + "' "
                + "MATCH (g) - [r:IS_GURU_OF] ->(s) "
                + " WHERE r.status <> '2' "
                + "AND g.OTSessionId IS NOT NULL RETURN g.OTSessionId,g.uuid"].join('\n');
            logger.debug("query: Retrieving OTSessionId & UUID of Guru: "); logger.debug(query);

            graph.query(query, function (err, results) {
                if (err) {
                    logger.error("error: "); logger.error(err);
                    logger.info("Query failed");

                    res.json({
                        "statuscode": 200
                        , "msgkey": "otCredentials_retrieved_successfull"
                        , "gurus": []
                        , "v": version
                    });
                }

                if (results.length) {
                    logger.info("They are connected  & OTSessionId exists in db ");

                    logger.debug("results: "); logger.debug(results);
                    //Step 3: If IS_GURU_OF relation &OTSessionId found

                    var OTSessionIdArray = [];
                    var OTTokenArray = [];
                    var uuidArray = [];
                    results.forEach(function (result) {

                        var opentokSessionId = result["g.OTSessionId"];
                        uuidArray.push(result["g.uuid"]);
                        OTSessionIdArray.push(result["g.OTSessionId"]);

                        opentokToken = opentok.generateToken(opentokSessionId, {
                            role: "moderator",
                            expireTime: (new Date().getTime() / 1000) + (1 * 24 * 60 * 60)
                        });
                        OTTokenArray.push(opentokToken);

                    });

                    logger.debug("OTSessionIdArray: "); logger.debug(OTSessionIdArray);

                    var guruArray = [];
                    for (i = 0; i < uuidArray.length; i++) {
                        guruArray.push({ uuid: uuidArray[i], OTSessionId: OTSessionIdArray[i], OTToken: OTTokenArray[i] });
                    }

                    logger.info("otCredentials_retrieved_successful ");
                    logger.debug("guruArray: "); logger.debug(guruArray);

                    res.json({
                        "statuscode": 200
                        , "msgkey": "otCredentials_retrieved_successfull"
                        , "gurus": guruArray
                        , "v": version
                    });

                }  //end: if (results.length) { If IS_GURU_OF relation &OTSessionId are present
                else { // guru array empty

                    logger.info("guru array empty ");
                    res.json({
                        "statuscode": 200
                        , "msgkey": "otCredentials_retrieved_successfull"
                        , "gurus": []
                        , "v": version
                    });
                } //end :guru array empty
            }); //end: graph.query(query, function (err, results) {
        }
        else {
            logger.error("error: "); logger.error("wrong_input");

            res.json({
                "statuscode": 400
                , "msgkey": "wrong_input"
                , "gurus": []
                , "v": version
            });
        }
        //Step 2: If the user is Guru...
        //Step 2a. Retrieve the OTSessionId from mUser
        //Step 2b. If the OTSessionId is not presnet, then create a new SessionId and update database
        //Step 2c. Generate OTToken
        //Step 2d. Retrun OT credentials

        //Step 3: if the user is a Shishya
        //Step 3a. Retrieve the OTSessionIds of all his Gurus (uuid, openTokSessionId)
        //Step 3b. For each OTSessionIds of the Gurus, generate OTToken
        //Step 3c. Return OT Credentials
    });


    /**
 * @api {post} /users/:id/shishyas Invites User
 * @apiVersion 0.3.0
 * @apiName PostShishya
 * @apiGroup Users
 * @apiPermission none
 *
 * @apiDescription This api is called when the Guru adds another person as his Shishya.
 * If the user already exists, then created relation else create invite node and make the relation between them.
 * 
 * @apiParam {shishyaCountryCode} int Shishyas countryCode
 * @apiParam {shishyaMobileNumber} String Shishyas mobileNumber
 * @apiParam {shishyaFirstName} String Shishyas First Name
 * @apiParam {shishyaLastName} String Shishyas Last Name
 *  @apiParam {secToken} String Users Security Token
 * 
 * @apiSuccess {int} statuscode  Status Code
 * @apiSuccess {String} msgkey Message Key
 * @apiSuccess {String} v version
 *
 * @apiSuccessExample Success-Response:
 *     HTTP/1.1 200 OK
 *     {
 *       "statuscode": 200,
 *       "msgkey": "inviteUser.success"
 *       "v": "1.0"
 *     }
 * 
 * @apiError Error in Database
 *
 * @apiErrorExample Error-Response:
 *     HTTP/1.1 404 Not Found
 *     {
 *        "statuscode": 203,
 *        "msgkey": "DB_failure",
 *        "v": version
 *     }
 */

    //POST /users/id/shishya
    //This api is called when the Guru adds another person as his Shishya
    router.post(BASE_API_URL + '/users/:id/shishyas', function (req, res) {
        logger.info("Inside shishyas [POST]");

        //Step 0: declare local variables
        var query, ShishyasUuid, props, parameters, guruName;

        //Step 1: Parse the input parameters
        var uuid = req.params['id'];

        var shishyaCountryCode = req.body.shishyaCountryCode;
        var shishyaMobileNumber = req.body.shishyaMobileNumber;
        var shishyaFirstName = req.body.shishyaFirstName;
        var shishyaLastName = req.body.shishyaLastName;

        logger.debug("req.params: "); logger.debug(req.params);
        logger.debug("req.body: "); logger.debug(req.body);

        var date = new Date();
        var day = date.getDate();
        var month = (date.getMonth() + 1);
        var year = date.getFullYear();
        var hour = date.getHours();
        var min = date.getMinutes();
        var sec = date.getSeconds();
        var milliSec = date.getMilliseconds();
        var todaysDate = year * Math.pow(10, 13) + month * Math.pow(10, 11) + day * Math.pow(10, 9) + hour * Math.pow(10, 7) + min * Math.pow(10, 5) + sec * Math.pow(10, 3) + milliSec;

        logger.debug("todaysDate: "); logger.debug(todaysDate);

        //Step 2: Check if the mUser node for Shishya exists
        query = ["MATCH (n:mUser) WHERE n.countryCode = " + shishyaCountryCode + " "
            + "AND n.mobileNumber = '" + shishyaMobileNumber + "' "
            + "RETURN n.uuid"].join('\n');

        logger.debug("query: Check if the mUser node for Shishya exists: "); logger.debug(query);

        graph.query(query, function (err, results) {
            if (err) {
                logger.error("error: "); logger.error(err);
                logger.info("Query failed");

                //This to be change in v2
                //Uncomment below code and inform to IOS & Android guys to test while DB shutdown/db password change
                //status. Best practice to use statuscode every where
                /* res.json({
                     "status": 203
                     , "msgkey": "DB Failure"
                     , "v": version
                 });*/
            }

            if (results.length) {
                //Step 3: If User exists ,check whether user is already related.
                logger.info("Shishya exists ");
                logger.debug("results: "); logger.debug(results);

                ShishyasUuid = results[0]["n.uuid"];

                query = ["MATCH (n1:mUser)-[r:IS_GURU_OF]-(n2:mUser) WHERE n1.uuid='" + uuid + "'  "
                    + " AND n2.uuid='" + ShishyasUuid + "' RETURN r.status"].join('\n');

                logger.debug("query: Checking shishya exists && shishya is already related: "); logger.debug(query);

                graph.query(query, function (err, results) {
                    if (err) {
                        logger.error("error: "); logger.error(err);
                        logger.info("Query failed");

                        /* res.json({
                             "statuscode": 200
                             , "msgkey": "inviteUser_success"
                             , "v": version
                         });*/
                    }

                    if (results.length) {
                        //Change the below code
                        //logger.info("Shishya already related with status 1 ");
                        logger.info("Shishya already related ");
                        logger.debug("results: "); logger.debug(results);

                        res.json({
                            "status": 203
                            , "msgkey": "already_in_relation"
                            , "v": version
                        });
                    }

                    else {
                        logger.info("Shishya not related, So create now ");
                        query = ["MATCH (g),(s)"
                            + "WHERE g.uuid='" + uuid + "' AND s.uuid='" + ShishyasUuid + "'"
                            + "SET s.isShishyaApproved = true "
                            + "CREATE UNIQUE (g)-[r:IS_GURU_OF {status:'0', requestSentDate:" + todaysDate + ", sentBy: '" + uuid + "'}]->(s)"
                            + "RETURN g,s,r"].join('\n');

                        logger.debug("query: If User exists...create Relationship: "); logger.debug(query);

                        graph.query(query, function (err, results) {
                            if (err) {
                                logger.error("error: "); logger.error(err);
                                logger.info("Query failed");

                                res.json({
                                    "statuscode": 200
                                    , "msgkey": "inviteUser_success"
                                    , "v": version
                                });
                            }
                            if (results.length) {
                                logger.info("Shishya relation created successful ");
                                logger.debug("results: "); logger.debug(results);
                                res.json({
                                    "statuscode": 200
                                    , "msgkey": "inviteUser_success"
                                    , "v": version
                                });
                            }
                        });
                    }
                });
            }
            //Step 4: User does not exist. Create new node and create Relationship

            else {
                logger.info("User does not exist ");

                props = { "countryCode": shishyaCountryCode, "mobileNumber": shishyaMobileNumber, isMobileNumberVerified: false, "firstName": shishyaFirstName, "lastName": shishyaLastName, "isShishyaApproved": true };
                logger.debug("props: "); logger.debug(props);
                parameters = {
                    "props": props
                };
                logger.debug("parameters: "); logger.debug(parameters);

                query = ["MATCH (g:mUser) WHERE g.uuid = '" + uuid + "' "
                    + "CREATE (s:mUser { props }) "
                    + "CREATE (g)-[r:IS_GURU_OF {status:'0', requestSentDate:" + todaysDate + ", sentBy: '" + uuid + "'}]->(s)"
                    + "RETURN s,r,g.firstName, g.lastName"].join('\n');
                logger.debug("query: create shishya & create Relationship: "); logger.debug(query);

                graph.query(query, parameters, function (err, results) {

                    if (err) {
                        logger.error("error: "); logger.error(err);
                        logger.info("Query failed");

                        res.json({
                            "status": 203
                            , "msgkey": "DB Failure"
                            , "v": version
                        });
                    }

                    if (results.length) { //user successfully created
                        logger.info("Shishya created & relation created successful ");
                        logger.debug("results: "); logger.debug(results);

                        guruName = results[0]["g.firstName"] + " " + results[0]["g.lastName"];
                        if ((guruName.length) > 65) { //70 Actually
                            guruName = guruName.substr(0, 65);
                        }

                        if (ignoreInviteSendSMS == false) {
                            //send SMS
                            var inviteMessage = "I am inviting you to download " + "\"" + "GuruSangeet Sky" + "\"" + " app. Use +" + shishyaCountryCode + "-" + shishyaMobileNumber + " to login. Sent by: " + guruName;

                            var phone = shishyaCountryCode + shishyaMobileNumber;

                            var smsOptions = {
                                mobiles: phone
                                , message: inviteMessage
                                , sender: 'GURUSG'
                                , route: '4'
                                , campaign: "New Folder"
                                , authkey: '116236Ae4ugsIj8576e6537'
                            };

                            logger.debug("sending SMS to " + smsOptions.mobiles);

                            request({
                                uri: "https://control.msg91.com/api/sendhttp.php"
                                , method: "POST"
                                , form: smsOptions
                            }, function (error, response, body) {
                                if (body != null) {
                                    res.json({
                                        "statuscode": 200
                                        , "msgkey": "inviteUser.success"
                                        , "v": version
                                    });
                                }
                                else {
                                    logger.info("MSG NOT SENT");
                                    res.json({
                                        "statuscode": 203
                                        , "msgkey": "MSG NOT SENT"
                                        , "v": version
                                    });
                                }
                            });
                        }
                        else {
                            logger.info("inviteUser.success.SMS_DISABLED");
                            res.json({
                                "statuscode": 200
                                , "msgkey": "inviteUser.success.SMS_DISABLED"
                                , "v": version
                            });
                        }

                    }
                    //No need of below code when we written if(err) above
                    else { //database error
                        logger.info("DB Failure");
                        res.json({
                            "status": 203
                            , "msgkey": "DB Failure"
                            , "v": version
                        });

                    }

                }); //end: graph.query(query, parameters, function (err, results) {

            } //end:  User does not exist. Create new node and create Relationship

        }); //end: graph.query(query, function (err, results) {

        //end of isShishya exists
        //Step 3: If Shishya's mUser node does not exits, then create a new node
        //Step 4: Create an IS_GURU_OF Relationship between guru and shishya
        //Step 5: Send invite SMS to Shishya
        //The SMS message includes sending a shortURL
    });



    /**
  * @api {delete} /users/:id/gurus/:guruId Decline invitation
  * @apiVersion 0.3.0
  * @apiName deletegurus
  * @apiGroup Users
  * @apiPermission none
  *
  * @apiDescription This api is called when the shishya declines a particular guru.
  * 
  * 
  * @apiParam {id} int Shishyas uuid
  * @apiParam {guruId} String gurus uuid
  * @apiParam {secToken} String Users Security Token
  * 
  * 
  * @apiSuccess {int} statuscode  Status Code
  * @apiSuccess {String} relationstatus Relation Status
  * @apiSuccess {String} msgkey Message Key
  * @apiSuccess {String} v version
  *
  * @apiSuccessExample Success-Response:
  *     HTTP/1.1 200 OK
  *     {
  *       "statuscode": 200,
  *       "relationstatuscode": 2
  *       "msgkey": "relation_declined_success"
  *       "v": "1.0"
  *     }
  * 
  * @apiError Error in Database
  *
  * @apiErrorExample Error-Response:
  *     HTTP/1.1 404 Not Found
  *    {
  *       "statuscode": 400,
  *       "status": "error",
  *       "msgkey": "guru's uuid / shishys's uuid is wrong",
  *       "v": "1.0"
 }
  */


    //DELETE /users/id/gurus/id
    //This api is called when the shishya declines a particular guru
    router.delete(BASE_API_URL + '/users/:id/gurus/:guruId', function (req, res) {
        logger.info("Inside guruId [DELETE]");

        //Step 0: declare local variables
        var query;

        var uuid = req.params['id'];
        var guruUuid = req.params['guruId'];
        logger.debug("req.params: "); logger.debug(req.params);

        //Step 2: Update the IS_GURU_OF relationships to set status = 'DECLINED'
        query = ["MATCH (s:mUser) WHERE s.uuid = '" + uuid + "' "
            + "MATCH (g:mUser) WHERE g.uuid = '" + guruUuid + "' "
            + " MATCH(g) - [r:IS_GURU_OF] ->(s)"
            + " SET r.status = '2' "
            + "RETURN r.status"].join('\n');

        logger.debug("query: Update the IS_GURU_OF relationships to set status = 'DECLINED': "); logger.debug(query);

        graph.query(query, function (err, results) {
            if (err) {
                logger.error("error: "); logger.error(err);
                logger.info("Query failed");

                res.json({
                    "statuscode": 400
                    , "status": "error"
                    , "msgkey": "guru's uuid / shishys's uuid is wrong"
                    , "v": version
                });
            }

            if (results.length) {//Relation declined set
                logger.info("Relation deleted successful ");
                logger.debug("results: "); logger.debug(results);
                res.json({
                    "statuscode": 200
                    , "relationstatuscode": results[0]["r.status"]
                    , "msgkey": "relation_declined_success"
                    , "v": version
                });

            }//end: Relation declined set
            else {//Relation not declined set 
                logger.error("error: "); logger.error("guru's uuid / shishys's uuid is wrong");

                res.json({
                    "statuscode": 400
                    , "status": "error"
                    , "msgkey": "guru's uuid / shishys's uuid is wrong"
                    , "v": version
                });
            } //end: Relation not declined set 
        }); //end: graph.query(query, function (err, results) {
    });


    /**
   * @api {get} /users/:id/shishyas Get shishyas list
   * @apiVersion 0.3.0
   * @apiName GetShishya
   * @apiGroup Users
   * @apiPermission none
   *
   * @apiDescription This api is invoked to get the list of the user's shishyas.
   * 
   * 
   * @apiParam {id} String Gurus uuid
   * @apiParam {secToken} String Gurus Security Token
   * 
   * @apiSuccess {int} statuscode  Status Code
   * @apiSuccess {String} status Status
   * @apiSuccess {String} firstName First Name
   * @apiSuccess {String} lastName Last Name
   * @apiSuccess {String} uuid uuid
   * @apiSuccess {String} msgkey Message Key
   * @apiSuccess {int} countryCode Country Code
   * @apiSuccess {String} mobileNumber Mobile Number
   * @apiSuccess {String} v version
   *
   * @apiSuccessExample Success-Response:
   *     HTTP/1.1 200 OK
   *     {
   *       "statuscode": 200,
   *       "shishyas": [
   *           {
   *           "status": "0",
   *           "firstName": "Soumya",
   *           "lastName": "Jg",
   *           "uuid": "6d051190b08011e6b0e986312c27d6db",
   *           "countryCode": 91,
   *           "mobileNumber": "8762289733"
   *     },
   *           {
   *           "status": "0",
   *           "firstName": "SFName",
   *           "lastName": "SLName",
   *           "uuid": "491675d0b08011e6b0e986312c27d6db",
   *           "countryCode": 91,
   *           "mobileNumber": "9448505697"
   *           }
   *        ],
   *       "v": "1.0"
   *     }
   * 
   * 
   * @apiError Error in Database
   *
   * @apiErrorExample Error-Response:
   *     HTTP/1.1 404 Not Found
   *     {
   *        "statuscode": 200,
   *        "shishyas": [],
   *        "v": "1.0"
   *     }
   */


    //GET /users/id/shishyas
    //This api is invoked to get the list of the user's shishyas.
    router.get(BASE_API_URL + '/users/:id/shishyas', function (req, res) {
        logger.info("Inside shishyas [GET]");

        //Step 0: declare local variables
        var query;

        var uuid = req.params['id'];
        logger.debug("req.params: "); logger.debug(req.params);

        query = ["MATCH (g:mUser) WHERE g.uuid = '" + uuid + "' "
            + "MATCH (g) - [r:IS_GURU_OF] ->(s) "
            + " WHERE r.status <> '2' "
            + "RETURN r.status as status, s.firstName as firstName,s.lastName as lastName, s.uuid as uuid, s.countryCode as countryCode, s.mobileNumber as mobileNumber"].join('\n');

        logger.debug("query: If IS_GURU_OF relation found ,retriving Shishyas details with relation: "); logger.debug(query);

        graph.query(query, function (err, results) {
            if (err) {
                logger.error("error: "); logger.error(err);
                logger.info("Query failed");

                /*  res.json({
                      "statuscode": 200
                      , "msgkey": "get_shishyas_success"
                      , "shishyas": error
                      , "v": version
                  });*/
            }

            //Step 3: If IS_GURU_OF relation found
            if (results.length) {
                logger.info("IS_GURU_OF relation found ");
                logger.debug("results: "); logger.debug(results);
                res.json({
                    "statuscode": 200
                    , "msgkey": "get_shishyas_success"
                    , "shishyas": results
                    , "v": version
                });
            } //end: if (results.length) { If IS_GURU_OF relation is present

            else { // shishyas array empty
                logger.info("No shishyas found ");

                res.json({
                    "statuscode": 200
                    , "msgkey": "get_shishyas_success"
                    , "shishyas": results
                    , "v": version
                });
            } //end :Shishya array empty
        }); //end: graph.query(query, function (err, results) {
    });

    /**
   * @api {get} /users/:id/gurus Get Gurus list
   * @apiVersion 0.3.0
   * @apiName Getgurus
   * @apiGroup Users
   * @apiPermission none
   *
   * @apiDescription This api is invoked to get the list of the user's gurus.
   * 
   * 
   * @apiParam {id} String Gurus uuid
   * @apiParam {secToken} String Gurus Security Token
   * 
   * @apiSuccess {int} statuscode  Status Code
   * @apiSuccess {String} status Status
   * @apiSuccess {String} firstName First Name
   * @apiSecret {String} lastName Last Name
   * @apiSuccess {String} uuid uuid
   * @apiSuccess {String} msgkey Message Key
   * @apiSuccess {int} countryCode Country Code
   * @apiSuccess {String} mobileNumber Mobile Number
   * @apiSuccess {String} v version
   *
   * @apiSuccessExample Success-Response:
   *     HTTP/1.1 200 OK
   *     {
   *       "statuscode": 200,
   *       "gurus": [
   *           {
   *           "status": "0",
   *           "firstName": "Soumya",
   *           "lastName": "Jg",
   *           "uuid": "6d051190b08011e6b0e986312c27d6db",
   *           "countryCode": 91,
   *           "mobileNumber": "8762289733"
   *     },
   *           {
   *           "status": "0",
   *           "firstName": "SFName",
   *           "lastName": "SLName",
   *           "uuid": "491675d0b08011e6b0e986312c27d6db",
   *           "countryCode": 91,
   *           "mobileNumber": "9448505697"
   *           }
   *        ],
   *       "v": "1.0"
   *     }
   * 
   * 
   * @apiError Error in Database
   *
   * @apiErrorExample Error-Response:
   *     HTTP/1.1 404 Not Found
   *     {
   *        "statuscode": 200,
   *        "gurus": [],
   *        "v": "1.0"
   *     }
   */


    //GET /users/id/gurus
    //This api is invoked to get the list of the user's gurus.
    router.get(BASE_API_URL + '/users/:id/gurus', isNeo4jOn, function (req, res) {
        logger.info("Inside gurus [GET]");

        //Step 0: declare local variables
        var query;

        var uuid = req.params['id'];
        logger.debug("req.params: "); logger.debug(req.params);

        query = ["MATCH (s:mUser) WHERE s.uuid = '" + uuid + "' "
            + "MATCH (g) - [r:IS_GURU_OF] ->(s) "
            + " WHERE r.status <> '2' "
            + "RETURN r.status as status, g.firstName as firstName, g.lastName as lastName, g.uuid as uuid, g.countryCode as countryCode, g.mobileNumber as mobileNumber"].join('\n');

        logger.debug("query: If IS_GURU_OF relation found, retriving guru details with relation: "); logger.debug(query);

        graph.query(query, function (err, results) {
            if (err) {
                logger.error("error: "); logger.error(err);
                logger.info("Query failed");

                /* res.json({
                     "statuscode": 200
                     , "msgkey": "get_guru_success"
                     , "gurus": "error"
                     , "v": version
                 });*/
            }
            if (results.length) { //Step 3: If IS_GURU_OF relation found
                logger.info("IS_GURU_OF relation found, guru details retrieved ");
                logger.debug("results: "); logger.debug(results);

                res.json({
                    "statuscode": 200
                    , "msgkey": "get_guru_success"
                    , "gurus": results
                    , "v": version
                });

            }//end: if (results.length) { If IS_GURU_OF relation is present
            else {// guru array empty
                logger.info("No gurus found ");
                res.json({
                    "statuscode": 200
                    , "msgkey": "get_guru_success"
                    , "gurus": results
                    , "v": version
                });
            } //end :guru array empty
        }); //end: graph.query(query, function (err, results) {
    });

    /**
  * @api {post} /classes Create class node
  * @apiVersion 0.3.0
  * @apiName Postclass
  * @apiGroup Class
  * @apiPermission none
  *
  * @apiDescription  This api is invoked when a new class has begun.
  * 
  * @apiParam {secToken} String Users Security Token
  * @apiParam {participants[]} String[] Paticepants
  * @apiParam {uuid} String uuid of the participants
  * @apiParam {role} Boolean Role of the participants
  * @apiParam {OTToken} String OT Token of the Paticepants
  *
  * @apiSuccess {int} statuscode  Status Code
  * @apiSuccess {String} msgkey Message Key
  * @apiSuccess {String} uuid uuid of the User
  * @apiSuccess {String} v version
  *
  * @apiSuccessExample Success-Response:
  *     HTTP/1.1 200 OK
  *     {
  *       "statuscode": 200,
  *       "msgkey": "class_created_successfully",
  *       "uuid": "c89f0220ae6611e68bb33a84bb3e39cf"
  *     }
  * 
  * @apiError Error in Database
  *
  * @apiErrorExample Error-Response:
  *     HTTP/1.1 404 Not Found
  *     {
  *        "statuscode": 203,
  *        "msgkey": "DB_failure",
  *        "v": version
  *     }
  */


    //POST /classes
    //This api is invoked when a new class has begun
    router.post(BASE_API_URL + '/classes', function (req, res) {
        logger.info("Inside classes [POST]");

        var data = req.body.participants;

        var date = new Date();
        var day = date.getDate();
        var month = (date.getMonth() + 1);
        var year = date.getFullYear();
        var hour = date.getHours();
        var min = date.getMinutes();
        var sec = date.getSeconds();
        var milliSec = date.getMilliseconds();
        var todaysDate = year * Math.pow(10, 13) + month * Math.pow(10, 11) + day * Math.pow(10, 9) + hour * Math.pow(10, 7) + min * Math.pow(10, 5) + sec * Math.pow(10, 3) + milliSec;

        var query1 = "";
        var query3 = "";
        var query2 = "CREATE (c:mClass { startTime: " + todaysDate + ",  status: '1'})";
        var query4 = "RETURN id(c)";

        for (var i = 0, j = 1; i < data.length; i++ , j++) {

            query1 = query1 + "MATCH(u" + j + ":mUser) WHERE u" + j + ".uuid = " + "'" + data[i]['uuid'] + "'";
            query3 = query3 + "CREATE (c) - [r" + j + ":IS_PARTICIPANT {role: " + "'" + data[i]['role'] + "'" + ", OTToken: " + "'" + data[i]['OTToken'] + "'" + " }] ->(u" + j + ")";

        }

        query = query1 + " " + query2 + " " + query3 + " " + query4;
        graph.query(query, function (err, results) {

            var id = results[0]['id(c)'];
            var query5 = "MATCH (n) WHERE id(n) = " + id + " RETURN n.uuid";
            if (results.length) {

                graph.query(query5, function (err, results) {
                    if (results.length) {
                        var uuid = results[0]['n.uuid'];

                        res.send({
                            "statuscode": 200
                            , "msgkey": "class_created_successfully"
                            , "uuid": uuid
                            , "v": version
                        })

                    } else {
                        res.send({
                            "statuscode": 400
                            , "status": "class_created_fail"
                            , "uuid": uuid
                            , "v": version
                        })

                    }

                }); //end: graph.query(query, function (err, results) {

            }
            else {
                res.send({
                    "statuscode": 400
                    , "status": "error"
                    , "status": "class_created_fail"
                    , "uuid": uuid
                })
            }

        });


    });

    /**
   * @api {put} /classes Update class node
   * @apiVersion 0.3.0
   * @apiName Putclass
   * @apiGroup Class
   * @apiPermission none
   *
   * @apiDescription  This api is invoked when a class ends.
   * 
   * @apiParam {uuid} String uuid of the participants
   * @apiParam {secToken} String Users Security Token
   *
   * @apiSuccess {int} statuscode  Status Code
   * @apiSuccess {String} msgkey Message Key
   * @apiSuccess {String} v version
   *
   * @apiSuccessExample Success-Response:
   *     HTTP/1.1 200 OK
   *     {
   *       "statuscode": 200,
   *       "msgkey": "class_created_successfully",
   *       "uuid": "c89f0220ae6611e68bb33a84bb3e39cf"
   *     }
   * 
   * @apiError Error in Database
   *
   * @apiErrorExample Error-Response:
   *     HTTP/1.1 404 Not Found
   *     {
   *        "statuscode": 404,
   *        "status": "error"
   *        "msgkey": "class_updated_fail",
   *        "v": "1.0"
   *     }
   * 
   * 
   */


    //PUT /classes
    //This api is invoked when a class ends
    router.put(BASE_API_URL + '/classes', function (req, res) {
        logger.info("Inside classes [PUT]");

        var uuid = req.body.uuid;

        var date = new Date();
        var day = date.getDate();
        var month = (date.getMonth() + 1);
        var year = date.getFullYear();
        var hour = date.getHours();
        var min = date.getMinutes();
        var sec = date.getSeconds();
        var milliSec = date.getMilliseconds();
        var todaysDate = year * Math.pow(10, 13) + month * Math.pow(10, 11) + day * Math.pow(10, 9) + hour * Math.pow(10, 7) + min * Math.pow(10, 5) + sec * Math.pow(10, 3) + milliSec;

        query = ["MATCH (c:mClass) WHERE c.uuid = '" + uuid + "' "
            + "SET c.endTime= " + todaysDate + ", c.status= '2' "
            + "RETURN c"].join('\n');
        console.log(query);

        graph.query(query, function (err, results) {
            console.log("results: "); console.log(results);

            if (results.length) {
                res.send({
                    "statuscode": 200
                    , "msgkey": "class_updated_successfully"
                    , "v": version
                })
            }
            else {
                res.send({
                    "statuscode": 400
                    , "status": "error"
                    , "msgkey": "class_updated_fail"
                    , "v": version
                })
            }

        });

    });

    //POST /users/:id/showForm when  user is not approved
    //This api is invoked when a class ends
    router.post(BASE_API_URL + '/users/:id/showForm', function (req, res) {
        logger.info("Inside showForm [POST]");

        var query, uuid, isMobileNumberVerified, userData, props, UserRecords, role;
        var uuid = req.params['id'];

        var email = req.body.email;
        var preferredTime = req.body.preferredTime;
        var isGuru = req.body.isGuru;

        var isShishya = req.body.isShishya;
        var guruName = req.body.guruName;
        var guruEmail = req.body.guruEmail;
        var guruMobileNumber = req.body.guruMobileNumber;

        logger.debug("req.params: "); logger.debug(req.params);
        logger.debug("req.body: "); logger.debug(req.body);

        var date = new Date();
        var day = date.getDate();
        var month = (date.getMonth() + 1);
        var year = date.getFullYear();
        var hour = date.getHours();
        var min = date.getMinutes();
        var sec = date.getSeconds();
        var milliSec = date.getMilliseconds();
        var todaysDate = year * Math.pow(10, 13) + month * Math.pow(10, 11) + day * Math.pow(10, 9) + hour * Math.pow(10, 7) + min * Math.pow(10, 5) + sec * Math.pow(10, 3) + milliSec;

        logger.debug("todaysDate: "); logger.debug(todaysDate);

        if (isGuru == "true") {
            isGuru = true;
            role = "guru";
        }

        else if (isShishya == "true") {
            isShishya = true;
            role = "shishya";
        }

        if (isGuru) {
            role = "guru";
            props = { "email": email, "preferredTime": preferredTime, "isGuru": true };

        } else if (isShishya) {
            role = "shishya";
            props = { "email": email, "preferredTime": preferredTime, "isShishya": true, "guruName": guruName, "guruEmail": guruEmail, "guruMobileNumber": guruMobileNumber };
        }

        var parameters = {
            "props": props
        };

        logger.debug("role: "); logger.debug(role);
        logger.debug("parameters: "); logger.debug(parameters);

        query = ["MATCH (n:mUser) WHERE n.uuid = '" + uuid + "' "
            + "RETURN n.countryCode, n.mobileNumber, n.firstName, n.lastName"].join('\n');

        logger.debug("query: Retriving user details: "); logger.debug(query);

        graph.query(query, function (err, results) {

            if (err) {
                logger.error("error: "); logger.error(err);
                logger.info("Query failed");

                res.json({
                    "statuscode": 400
                    , "msgkey": "showForm_failure"
                    , "v": version
                });
            }

            if (results.length) {
                logger.info("User details retrivied");
                logger.debug("results: "); logger.debug(results);

                var countryCode = results[0]["n.countryCode"]
                var mobileNumber = results[0]["n.mobileNumber"]
                var firstName = results[0]["n.firstName"]
                var lastName = results[0]["n.lastName"]

                if (isGuru) {
                    records = [
                        {
                            "First Name": firstName,
                            "Last Name": lastName,
                            "Email": email,
                            "Title": role,
                            "Phone": "+" + countryCode + " " + mobileNumber,
                            "Description": preferredTime
                        }
                    ];

                    logger.debug("records: "); logger.debug(records);
                    UserRecords = ", Email: " + email + ", preferredTime: " + preferredTime;
                    logger.debug("UserRecords: "); logger.debug(UserRecords);

                } else if (isShishya) {
                    records = [
                        {
                            "First Name": firstName + " " + lastName,
                            "Last Name": guruName,
                            "Email": email,
                            "Secondary Email": guruEmail,
                            "Title": role,
                            "Phone": "+" + countryCode + " " + mobileNumber,
                            "Mobile": guruMobileNumber,
                            "Description": preferredTime
                        }
                    ];

                    logger.debug("records: "); logger.debug(records);
                    UserRecords = ", Email: " + email + ", preferredTime: " + preferredTime + ", MyGuru Name: " + guruName + ", Myguru phone: " + "+" + guruMobileNumber + ", MyGuru Email: " + guruEmail;
                    logger.debug("UserRecords: "); logger.debug(UserRecords);
                }

                query = ["MATCH (gs:mUser) WHERE gs.uuid = '" + uuid + "' "
                    + "CREATE (c:ContactRequest { props }) "
                    + "CREATE (gs)-[r:SUBMITTED {requestSentDate:" + todaysDate + "}]->(c)"
                    + "RETURN gs,c,r"].join('\n');

                logger.debug("query: To relate ContactRequest node with SUBMITTED link: "); logger.debug(query);

                graph.query(query, parameters, function (err, results) {

                    if (err) {
                        logger.error("error: "); logger.error(err);
                        logger.info("Query failed");

                        /* res.json({
                             "statuscode": 400
                             , "msgkey": "showForm_failure"
                             , "v": version
                         });*/
                    }

                    if (results.length) {
                        logger.info("ContactRequest node with SUBMITTED link sucessful");
                        logger.debug("results: "); logger.debug(results);

                        query = ["MATCH (n:mUser) WHERE n.uuid = '" + uuid + "' "
                            + "RETURN n.countryCode, n.mobileNumber, n.firstName, n.lastName"].join('\n');

                        logger.debug("query: Retriving user details: "); logger.debug(query);

                        graph.query(query, function (err, results) {

                            if (err) {
                                logger.error("error: "); logger.error(err);
                                logger.info("Query failed");

                                res.json({
                                    "statuscode": 400
                                    , "msgkey": "showForm_failure"
                                    , "v": version
                                });
                            }

                            if (results.length) {
                                logger.info("User details retrived ");
                                logger.debug("results: "); logger.debug(results);

                                var inviteMessage = "This " + role + " " + results[0]["n.countryCode"] + results[0]["n.mobileNumber"] + " Trying to login " + "Name: " + results[0]["n.firstName"] + " " + results[0]["n.lastName"];

                                var mailOptions = {
                                    from: '"Guru Sangeet User " ' + email, // sender address
                                    to: 'krishnamurthy@msangeet.com', // list of receivers separated by ,
                                    subject: 'New GuruSangeet user loggedIn ✔', // Subject line
                                    text: 'Hello krishnamurthy !', // plaintext body
                                    html: '<b>' + inviteMessage + " " + UserRecords + '</b>' // html body
                                };

                                if (ignoreLoginSendSMS == false) {
                                    var phone = "919448505697";
                                    var smsOptions = {
                                        mobiles: phone
                                        , message: inviteMessage
                                        , sender: 'GURUSG'
                                        , route: '4'
                                        , campaign: "New Folder"
                                        , authkey: '116236Ae4ugsIj8576e6537'
                                    };

                                    logger.debug("sending SMS to " + smsOptions.mobiles);

                                    request({
                                        uri: "https://control.msg91.com/api/sendhttp.php"
                                        , method: "POST"
                                        , form: smsOptions
                                    }, function (error, response, body) {

                                        if (error) {
                                            logger.debug("error: "); logger.debug(error);
                                        }

                                        if (body != null) {

                                            zoho.execute('crm', 'Leads', 'insertRecords', records, function (err, result) {
                                                if (err !== null) {
                                                    logger.debug("err"); logger.debug(err);
                                                } else if (result.isError()) {
                                                    logger.debug("result.message"); logger.debug(result.message);
                                                } else {
                                                    logger.debug("result.data"); logger.debug(result.data);

                                                    //send email via gmail
                                                    transporter.sendMail(mailOptions, function (error, info) {
                                                        if (error) {
                                                            return console.log(error);
                                                        }
                                                        logger.info("showForm success ");
                                                        res.json({
                                                            "statuscode": 200
                                                            , "msgkey": "showForm_success"
                                                            , "v": version
                                                        });

                                                        logger.debug("Message sentinfo"); logger.debug(info);

                                                    });

                                                }
                                            });
                                        }
                                        else {
                                            logger.info("MSG NOT SENT ");
                                            res.json({
                                                "statuscode": 203
                                                , "msgkey": "MSG NOT SENT"
                                                , "v": version
                                            });
                                        }
                                    });
                                }
                                else {
                                    zoho.execute('crm', 'Leads', 'insertRecords', records, function (err, result) {
                                        if (err !== null) {
                                            logger.debug("err"); logger.debug(err);
                                        } else if (result.isError()) {
                                            logger.debug("result.message"); logger.debug(result.message);
                                        } else {
                                            logger.debug("result.data"); logger.debug(result.data);
                                            //send email via gmail
                                            transporter.sendMail(mailOptions, function (error, info) {
                                                if (error) {
                                                    return console.log(error);
                                                }

                                                res.json({
                                                    "statuscode": 200
                                                    , "msgkey": "showForm_success_SendSMS_disabled"
                                                    , "v": version
                                                });

                                                logger.debug("Message sentinfo"); logger.debug(info);

                                            });
                                        }
                                    });
                                }

                            }//end: if (results.length) { //User exists... return the user details
                            else {
                                logger.error("error: showForm_failure");
                                res.json({
                                    "statuscode": 400
                                    , "msgkey": "showForm_failure"
                                    , "v": version
                                });
                            }
                        }); //end: graph.query(query, function (err, results) {
                    }
                });
            }
            else {
                logger.error("showForm_failure");

                res.json({
                    "statuscode": 400
                    , "msgkey": "showForm_failure"
                    , "v": version
                });
            }
        });
    });







    //Admin get the show Form details
    router.get(BASE_API_URL + '/admin/showForm', function (req, res) {
        var query, uuid, isMobileNumberVerified, userData, props;

        query = ["MATCH (n:mUser) - [r:SUBMITTED] - (c:ContactRequest) "
            + "WHERE n.isGuruApproved=false or n.isShishyaApproved=false "
            + "RETURN n.uuid as uuid, n.firstName as firstName , n.lastName as lastName, n.countryCode as countryCode, "
            + "n.mobileNumber as mobileNumber, c.isGuru as isGuru, c.isShishya as isShishya, c.email as email, "
            + "c.preferredTime as preferredTime, c.guruEmail as guruEmail, c.guruMobileNumber as guruMobileNumber, "
            + "c.guruName as guruName"].join('\n');

        logger.debug("query1"); logger.debug(query);

        graph.query(query, function (err, results) {
            if (results.length) {
                res.json({
                    "statuscode": 200
                    , "msgkey": "user_details_retrieved"
                    , "pendinglist": results
                    , "v": version
                });
            }
            else {
                res.json({
                    "statuscode": 400
                    , "msgkey": "no_pendings_found"
                    , "pendinglist": results
                    , "v": version
                });
            }
        });
    });


    // GET /admin/users/id={uuid}/basicProfile
    // This API gives uuid,countryCode,mobileNumber,firstName, lastName,isGuru,isShishya,isAdmin
    router.get(BASE_API_URL + '/admin/users/:id/basicProfile', function (req, res) {

        logger.info("Inside Admin basicProfile [GET]");

        //Step 0: Local Variable Declarations

        //Step 1: Parse Request Parameters

        var uuid = req.params['id'];

        query = ["MATCH (n:mUser) WHERE n.uuid = '" + uuid + "' "
            + "RETURN n.uuid, n.countryCode, n.mobileNumber, n.firstName, n.lastName,n.isGuru, n.isShishya, n.isAdmin, n.isGuruApproved, n.isShishyaApproved "].join('\n');

        console.log(query);

        graph.query(query, function (err, results) {


            if (results.length) {
                logger.debug("results: "); logger.debug(results);
                res.json({
                    "statuscode": 200
                    , "msgkey": "user_already_exist"
                    , "uuid": results[0]["n.uuid"]
                    , "countryCode": results[0]["n.countryCode"]
                    , "mobileNumber": results[0]["n.mobileNumber"]
                    , "firstName": results[0]["n.firstName"]
                    , "lastName": results[0]["n.lastName"]
                    , "isGuru": results[0]["n.isGuru"]
                    , "isShishya": results[0]["n.isShishya"]
                    , "isAdmin": results[0]["n.isAdmin"]
                    , "isGuruApproved": results[0]["n.isGuruApproved"]
                    , "isShishyaApproved": results[0]["n.isShishyaApproved"]
                    , "v": version
                });

            }//end: if (results.length) { /Users [POST] API 12345/User exists... return the user details
            else {
                res.json({
                    "statuscode": 400
                    , "msgkey": "basicProfile_failure"
                    , "uuid": null
                    , "countryCode": null
                    , "mobileNumber": null
                    , "firstName": null
                    , "lastName": null
                    , "isGuru": null
                    , "isShishya": null
                    , "isAdmin": null
                    , "isGuruApproved": null
                    , "isShishyaApproved": null
                    , "v": version
                });

            } //end :BasicProfile details failure
        }); //end: graph.query(query, function (err, results) {

    });


    // GET admin/users
    // This API is for admin & is invoked to to find the user exists or not.
    // If the user already exists
    // Return the basic details of the user

    // router.get(BASE_API_URL + '/admin/users/:countryCode/:mobileNumber', function (req, res) {
    router.get(BASE_API_URL + '/admin/users', function (req, res) {
        logger.info("Inside Admin users [GET]");

        //Step 0: Local Variable Declarations
        var query, uuid, isMobileNumberVerified, userData, props;

        logger.info("Inside /admin/users [GET]");
        //Step 1: Parse Request Parameters

        /* var countryCode = req.params['countryCode'];
         var mobileNumber = req.params['mobileNumber'];*/

        var countryCode = req.query['countryCode'];
        var mobileNumber = req.query['mobileNumber'];

        logger.debug("countryCode- " + countryCode);
        logger.debug("mobileNumber- " + mobileNumber);

        //Step 2: Check if the user already exists
        query = ["MATCH (n:mUser) WHERE n.countryCode = " + countryCode + " "
            + "AND n.mobileNumber = '" + mobileNumber + "' "
            + "RETURN n.uuid, n.countryCode, n.mobileNumber, n.firstName, n.lastName,n.isGuru, n.isShishya, n.isAdmin "].join('\n');
        logger.debug("query1"); logger.debug(query);

        graph.query(query, function (err, results) {
            logger.info("Inside graph query1 function");
            logger.debug("results1"); logger.debug(results);

            //Step 3: If User exists... return the user details
            if (results.length) {
                logger.info("Inside if(query1: results.length)");

                res.json({
                    "statuscode": 200
                    , "msgkey": "user_already_exist"
                    , "uuid": results[0]["n.uuid"]
                    , "countryCode": countryCode
                    , "mobileNumber": mobileNumber
                    , "firstName": results[0]["n.firstName"]
                    , "lastName": results[0]["n.lastName"]
                    , "isGuru": results[0]["n.isGuru"]
                    , "isShishya": results[0]["n.isShishya"]
                    , "isAdmin": results[0]["n.isAdmin"]
                    , "v": version
                });

            }
            //Step 4: User does not exist. Create new node and return user data
            else {
                res.json({
                    "statuscode": 400
                    , "msgkey": "user_does_not_exist"
                    , "v": version
                });

            } //end: if (results.length) { //User exists... return the user details

        }); //end: graph.query(query, function (err, results) {

    }); //end: router.post(BASE_API_URL + '/users', function (req, res) {



    //To find Admin Exists or not
    //Discuss with Sir
    // router.get(BASE_API_URL + '/admin/users/:countryCode/:mobileNumber/findAdmin', function (req, res) {
    router.get(BASE_API_URL + '/admin/users/findAdmin', function (req, res) {
        logger.info("Inside Admin findAdmin [GET]");

        //Step 0: Local Variable Declarations
        var query, uuid, isMobileNumberVerified, userData, props;

        logger.info("Inside /admin/users/findAdmin [GET]");
        //Step 1: Parse Request Parameters

        /* var countryCode = req.params['countryCode'];
         var mobileNumber = req.params['mobileNumber'];*/

        var countryCode = req.query['countryCode'];
        var mobileNumber = req.query['mobileNumber'];

        logger.debug("countryCode- " + countryCode);
        logger.debug("mobileNumber- " + mobileNumber);

        //Step 2: Check if the user already exists
        query = ["MATCH (n:mUser) WHERE n.countryCode = " + countryCode + " "
            + "AND n.mobileNumber = '" + mobileNumber + "' "
            + "RETURN n.uuid, n.isMobileNumberVerified, n.isAdmin "].join('\n');
        logger.debug("query1"); logger.debug(query);

        graph.query(query, function (err, results) {
            logger.info("Inside graph query1 function");
            logger.debug("results1"); logger.debug(results);

            //Step 3: If User exists... return the user details
            if (results.length) {
                logger.info("Inside if(query1: results.length)");

                res.json({
                    "statuscode": 200
                    , "msgkey": "user_already_exist"
                    , "uuid": results[0]["n.uuid"]
                    , "isMobileNumberVerified": results[0]["n.isMobileNumberVerified"]
                    , "isAdmin": results[0]["n.isAdmin"]
                    , "v": version
                });

            }
            //Step 4: User does not exist. Create new node and return user data
            else {
                res.json({
                    "statuscode": 400
                    , "msgkey": "admin_does_not_exista"
                    , "v": version
                });

            }

        });
    });


    // POST admin/users
    // This API is invoked to create a new mUser by admin.
    // Return the basic details of the user
    router.post(BASE_API_URL + '/admin/users', function (req, res) {
        logger.info("Inside Admin users [POST]");

        //Step 0: Local Variable Declarations
        var query, uuid, isMobileNumberVerified, userData, props;

        logger.info("Inside /admin/users [POST]");
        //Step 1: Parse Request Parameters
        var countryCode = req.body.countryCode;
        var mobileNumber = req.body.mobileNumber;
        var firstName = req.body.firstName;
        var lastName = req.body.lastName;
        //var isGuru = req.body.isGuru;
        //var isShishya = req.body.isShishya;
        var isGuru = req.query['isGuru'];
        var isShishya = req.query['isShishya'];

        console.log(req.body);
        console.log(req.query);


        if (req.query.isGuru == "true") {
            console.log("isGuru==true");
            isGuru = true;
        }
        else {
            console.log("isGuru==false");
            isGuru = false;
        }

        if (req.query.isShishya == "true") {
            isShishya = true;
        }
        else {
            isShishya = false;
        }

        query = ["MATCH (n:mUser) WHERE n.countryCode = " + countryCode + " "
            + "AND n.mobileNumber = '" + mobileNumber + "' "
            + "RETURN n.isMobileNumberVerified, n.uuid, n.isGuruApproved, n.isShishyaApproved, n.isBasicProfileSet"].join('\n');
        logger.debug("query: Check if the user already exists"); logger.debug(query);

        graph.query(query, function (err, results) {
            if (results.length) {
                res.json({
                    "statuscode": 200
                    , "msgkey": "user_already_exist"
                    , "uuid": results[0]["n.uuid"]
                    , "isMobileNumberVerified": results[0]["n.isMobileNumberVerified"]
                    , "isGuruApproved": results[0]["n.isGuruApproved"]
                    , "isShishyaApproved": results[0]["n.isShishyaApproved"]
                    , "isBasicProfileSet": results[0]["n.isBasicProfileSet"]
                    , "v": version
                });

            }
            //Step 4: User does not exist. Create new node and return user data
            else {
                logger.info("User does not exist");
                props = { "countryCode": parseInt(countryCode), "mobileNumber": mobileNumber, "isGuru": isGuru, "isShishya": isShishya, "isMobileNumberVerified": true, "firstName": firstName, "lastName": lastName, "isBasicProfileSet": true };


                if (isGuru == true) {
                    props["isGuruApproved"] = true;
                }
                else if (isShishya == true) {
                    props["isShishyaApproved"] = true;
                }
                var parameters = {
                    "props": props
                };
                logger.debug("props"); logger.debug(props);


                query = "CREATE (n:mUser { props }) RETURN n";
                logger.debug("query2"); logger.debug(query);

                graph.query(query, parameters, function (err, results) {
                    logger.info("Inside graph query2 function");
                    logger.debug("results2: "); logger.debug(results);
                    if (results.length) { //user successfully created
                        logger.info("query2 Inside if(query2: results2.length)");
                        //retrieve the uuid of the newly created user
                        query = ["MATCH (n:mUser) WHERE n.countryCode = " + countryCode + " "
                            + "AND n.mobileNumber = '" + mobileNumber + "' "
                            + "RETURN n.uuid, n.isMobileNumberVerified,n.countryCode,n.mobileNumber,n.firstName,n.lastName,n.isGuru,n.isShishya,n.isAdmin, n.isBasicProfileSet"].join('\n');
                        logger.debug("query3"); logger.debug(query);
                        graph.query(query, function (err, results) {
                            logger.info("Inside graph query3 function");
                            res.json({
                                "statuscode": 200
                                , "msgkey": "new_user_created"
                                , "uuid": results[0]["n.uuid"]
                                , "isMobileNumberVerified": isMobileNumberVerified
                                , "countryCode": results[0]["n.countryCode"]
                                , "mobileNumber": results[0]["n.mobileNumber"]
                                , "firstName": results[0]["n.firstName"]
                                , "lastName": results[0]["n.lastName"]
                                , "isGuru": results[0]["n.isGuru"]
                                , "isShishya": results[0]["n.isShishya"]
                                , "isAdmin": results[0]["n.isAdmin"]
                                , "isBasicProfileSet": results[0]["n.isBasicProfileSet"]
                                , "v": version
                            });
                        }); //end: graph.query(query, function (err, results) {

                    } else { //database error
                        logger.info("query2:Inside if (!results.length)");
                        logger.fatal("query2: DB_failure")
                        res.json({
                            "statuscode": 203
                            , "msgkey": "DB_failure"
                            , "v": version
                        });

                    } //end: if (restults.length) {

                }); //end: graph.query(query, parameters, function (err, results) {
            }
        });

    }); //end: router.post(BASE_API_URL + '/users', function (req, res) {


    // put admin/users
    // This API is invoked to update mUser by admin.
    // Return the basic details of the user
    router.put(BASE_API_URL + '/admin/users/:id', function (req, res) {
        logger.info("Inside Admin update basic profile [PUT]");

        var query, uuid, isMobileNumberVerified, userData, props;
        logger.info("Inside /admin/users/:id [PUT]");
        var uuid = req.params['id'];
        var countryCode = req.body.countryCode;
        var mobileNumber = req.body.mobileNumber;
        var firstName = req.body.firstName;
        var lastName = req.body.lastName;
        var isGuruApproved = req.body.isGuruApproved;
        var isShishyaApproved = req.body.isShishyaApproved;

        if (isGuruApproved === undefined) {
            isGuruApproved = null;
            logger.debug("isGuruApproved: value " + isGuruApproved);
        }
        if (isShishyaApproved === undefined) {
            isShishyaApproved = null;
            logger.debug("isShishyaApproved: value " + isShishyaApproved);
        }

        // var isGuru = req.body.isGuru;
        //  var isShishya = req.body.isShishya;
        var isGuru = req.query['isGuru'];
        var isShishya = req.query['isShishya'];

        console.log(req.body);
        console.log(req.query);

        if (req.query.isGuru == "true") {
            console.log("isGuru==true");
            isGuru = true;
        }
        else {
            console.log("isGuru==false");
            isGuru = false;
        }

        if (req.query.isShishya == "true") {
            isShishya = true;
        }
        else {
            isShishya = false;
        }

        logger.debug("isGuruApproved :" + isGuruApproved);
        logger.debug("isShishyaApproved :" + isShishyaApproved);

        query = ["MATCH (n:mUser) WHERE n.uuid = '" + uuid + "' "
            + "SET n.firstName = '" + firstName + "' "
            + " ,n.lastName = '" + lastName + "' "
            + " ,n.isMobileNumberVerified = " + true + " "
            + " ,n.isGuru=" + isGuru + " "
            + " ,n.isShishya=" + isShishya + " "
            + " ,n.isGuruApproved=" + isGuruApproved + " "
            + " ,n.isShishyaApproved=" + isShishyaApproved + " "
            + "RETURN n.uuid, n.isMobileNumberVerified, n.countryCode, n.mobileNumber, n.firstName, n.lastName, n.isGuru, n.isShishya, n.isAdmin, n.isGuruApproved, n.isShishyaApproved"].join('\n');

        logger.debug("query2"); logger.debug(query);

        graph.query(query, function (err, results) {
            if (results.length) { //user successfully created

                res.json({
                    "statuscode": 200
                    , "msgkey": "guru_Updated"
                    , "uuid": results[0]["n.uuid"]
                    , "isMobileNumberVerified": results[0]["n.isMobileNumberVerified"]
                    , "countryCode": results[0]["n.countryCode"]
                    , "mobileNumber": results[0]["n.mobileNumber"]
                    , "firstName": results[0]["n.firstName"]
                    , "lastName": results[0]["n.lastName"]
                    , "isGuru": results[0]["n.isGuru"]
                    , "isShishya": results[0]["n.isShishya"]
                    , "isAdmin": results[0]["n.isAdmin"]
                    , "isGuruApproved": results[0]["n.isGuruApproved"]
                    , "isShishyaApproved": results[0]["n.isShishyaApproved"]
                    , "v": version
                });

            } else { //database error
                logger.info("query2:Inside if (!results.length)");
                logger.fatal("query2: DB_failure")
                res.json({
                    "statuscode": 203
                    , "msgkey": "DB_failure"
                    , "v": version
                });
            } //end: if (restults.length) {
        }); //end: graph.query(query, parameters, function (err, results) {
    }); //end: router.post(BASE_API_URL + '/users', function (req, res) {


    //POST /admin/users/:guruUUID/shishyas/:shishyaUUID
    //This api is called when to invite Shishya
    //Guru added to shishya
    router.post(BASE_API_URL + '/admin/users/:guruUUID/shishyas/:shishyaUUID', function (req, res) {
        logger.info("Inside Admin invite Shishya [POST]");

        //Step 0: declare local variables

        //Step 1: Parse the input parameters
        console.log("Inside /admin/users/:guruUUID/shishyas/:shishyaUUID [POST]")
        var inviterID = req.params['guruUUID'];
        var inviteeID = req.params['shishyaUUID'];
        console.log(req.params);
        console.log(req.body);

        var date = new Date();
        var day = date.getDate();
        var month = (date.getMonth() + 1);
        var year = date.getFullYear();
        var hour = date.getHours();
        var min = date.getMinutes();
        var sec = date.getSeconds();
        var milliSec = date.getMilliseconds();
        var todaysDate = year * Math.pow(10, 13) + month * Math.pow(10, 11) + day * Math.pow(10, 9) + hour * Math.pow(10, 7) + min * Math.pow(10, 5) + sec * Math.pow(10, 3) + milliSec;


        query = ["MATCH (g),(s)"
            + " WHERE g.uuid='" + inviterID + "' AND s.uuid='" + inviteeID + "'"
            + " SET s.isShishyaApproved = true"
            + " CREATE UNIQUE (g)-[r:IS_GURU_OF {status:'1', requestSentDate:" + todaysDate + ", sentBy: '" + inviterID + "'}]->(s)"
            + " RETURN g, s.countryCode, s.mobileNumber, r, g.firstName, g.lastName"].join('\n');

        console.log("query"); console.log(query);

        graph.query(query, function (err, results) {
            console.log("results: "); console.log(results);
            var shishyaCountryCode = results[0]["s.countryCode"];
            var shishyaMobileNumber = results[0]["s.mobileNumber"];

            var guruName = results[0]["g.firstName"] + " " + results[0]["g.lastName"];

            if (ignoreInviteSendSMS == false) {
                //send SMS
                var inviteMessage = "I am inviting you to download " + "\"" + "GuruSangeet Sky" + "\"" + " app. Use +" + shishyaCountryCode + "-" + shishyaMobileNumber + " to login. Sent by: " + guruName;

                var phone = shishyaCountryCode + shishyaMobileNumber;

                var smsOptions = {
                    mobiles: phone
                    , message: inviteMessage
                    , sender: 'GURUSG'
                    , route: '4'
                    , campaign: "New Folder"
                    , authkey: '116236Ae4ugsIj8576e6537'
                };

                console.log("sending SMS to " + smsOptions.mobiles);
                request({
                    uri: "https://control.msg91.com/api/sendhttp.php"
                    , method: "POST"
                    , form: smsOptions
                }, function (error, response, body) {
                    if (body != null) {
                        res.json({
                            "statuscode": 200
                            , "msgkey": "inviteUser.success"
                            , "v": version
                        });
                    }
                    else {
                        res.json({
                            "statuscode": 203
                            , "msgkey": "MSG NOT SENT"
                            , "v": version
                        });
                    }
                });

            }
            else {
                res.json({
                    "statuscode": 200
                    , "msgkey": "inviteUser.success.SMS_DISABLED"
                    , "v": version
                });
            }

        });

    });


    //POST /admin/users/:shishyaUUID/gurus/:guruUUID
    //This api is called when to invite Guru
    //Shisya added to guru
    router.post(BASE_API_URL + '/admin/users/:shishyaUUID/gurus/:guruUUID', function (req, res) {
        logger.info("Inside Admin invite Guru [POST]");

        //Step 0: declare local variables

        //Step 1: Parse the input parameters
        console.log("Inside /admin/users/:shishyaUUID/gurus/:guruUUID [POST]")
        var inviterID = req.params['shishyaUUID'];
        var inviteeID = req.params['guruUUID'];

        console.log(req.params);
        console.log(req.body);

        var date = new Date();
        var day = date.getDate();
        var month = (date.getMonth() + 1);
        var year = date.getFullYear();
        var hour = date.getHours();
        var min = date.getMinutes();
        var sec = date.getSeconds();
        var milliSec = date.getMilliseconds();
        var todaysDate = year * Math.pow(10, 13) + month * Math.pow(10, 11) + day * Math.pow(10, 9) + hour * Math.pow(10, 7) + min * Math.pow(10, 5) + sec * Math.pow(10, 3) + milliSec;


        /* query = ["MATCH (g),(s)"
             + " WHERE g.uuid='" + inviterID + "' AND s.uuid='" + inviteeID + "'"
             + " SET g.isGuruApproved = true"
             + " CREATE UNIQUE (s)-[r:IS_GURU_OF {status:'1', requestSentDate:" + todaysDate + ", sentBy: '" + inviterID + "'}]->(g)"
             + " RETURN g,s,r"].join('\n');*/

        query = ["MATCH (g),(s)"
            + " WHERE g.uuid='" + inviteeID + "' AND s.uuid='" + inviterID + "'"
            + " SET g.isGuruApproved = true"
            + " CREATE UNIQUE (g)-[r:IS_GURU_OF {status:'1', requestSentDate:" + todaysDate + ", sentBy: '" + inviterID + "'}]->(s)"
            + " RETURN g,s,r"].join('\n');

        console.log("query"); console.log(query);

        graph.query(query, function (err, results) {
            console.log("results: "); console.log(results);
            res.json({
                "statuscode": 200
                , "msgkey": "inviteUser.success"
                , "v": version
            });

        });

    });


    //GET /admin/users/:guruUUID/shishyas/:shishyaUUID
    //This api is called to find is guru related with that shishya or not
    router.get(BASE_API_URL + '/admin/users/:guruUUID/shishyas/:shishyaUUID', function (req, res) {
        logger.info("Inside Admin find relation [GET]");

        //Step 0: declare local variables

        //Step 1: Parse the input parameters
        console.log("/admin/users/:guruUUID/shishyas/:shishyaUUID [GET]")
        var guruUUID = req.params['guruUUID'];
        var shishyaUUID = req.params['shishyaUUID'];

        console.log(req.params);
        console.log(req.body);

        query = ["MATCH (g)-[r:IS_GURU_OF]->(s) "
            + "WHERE g.uuid='" + guruUUID + "' AND s.uuid='" + shishyaUUID + "' AND r.status ='1'   "
            + "RETURN g,s,r"].join('\n');

        console.log("query"); console.log(query);

        graph.query(query, function (err, results) {
            console.log("results: "); console.log(results);

            if (results.length) {
                res.json({
                    "statuscode": 200
                    , "msgkey": "relation_found"
                    , "v": version
                });

            } else {
                res.json({
                    "statuscode": 200
                    , "msgkey": "relation_not_found"
                    , "v": version
                });
            }

        });

    });


    //Find user by firstName
    router.get(BASE_API_URL + '/admin/users/findByFirstName', function (req, res) {
        logger.info("Inside Admin findByFirstName [GET]");

        var query, uuid, isMobileNumberVerified, userData, props;
        var firstName = req.query['firstName'];

        logger.debug(req.query);

        query = ["MATCH (n:mUser) WHERE n.firstName = '" + firstName + "'"
            + "RETURN n.uuid, n.firstName, n.lastName,n.countryCode,n.mobileNumber,n.isMobileNumberVerified,n.isGuru,n.isShishya"].join('\n');
        logger.debug(query);

        graph.query(query, function (err, results) {
            if (results.length) {
                res.json({
                    "statuscode": 200
                    , "msgkey": "user_details"
                    , "uuid": results[0]["n.uuid"]
                    , "countryCode": results[0]["n.countryCode"]
                    , "mobileNumber": results[0]["n.mobileNumber"]
                    , "firstName": results[0]["n.firstName"]
                    , "lastName": results[0]["n.lastName"]
                    , "isMobileNumberVerified": results[0]["n.isMobileNumberVerified"]
                    , "isGuru": results[0]["n.isGuru"]
                    , "isShishya": results[0]["n.isShishya"]
                    , "v": version
                });

            }
        });

    });

    //Find user by Last Name
    router.get(BASE_API_URL + '/admin/users/findByLastName', function (req, res) {
        logger.info("Inside Admin findByLastName [GET]");

        var query, uuid, isMobileNumberVerified, userData, props;
        var lastName = req.query['lastName'];

        logger.debug(req.query);

        query = ["MATCH (n:mUser) WHERE n.lastName = '" + lastName + "'"
            + "RETURN n.uuid, n.firstName, n.lastName,n.countryCode,n.mobileNumber,n.isMobileNumberVerified,n.isGuru,n.isShishya"].join('\n');
        logger.debug(query);

        graph.query(query, function (err, results) {
            if (results.length) {
                res.json({
                    "statuscode": 200
                    , "msgkey": "user_details"
                    , "uuid": results[0]["n.uuid"]
                    , "countryCode": results[0]["n.countryCode"]
                    , "mobileNumber": results[0]["n.mobileNumber"]
                    , "firstName": results[0]["n.firstName"]
                    , "lastName": results[0]["n.lastName"]
                    , "isMobileNumberVerified": results[0]["n.isMobileNumberVerified"]
                    , "isGuru": results[0]["n.isGuru"]
                    , "isShishya": results[0]["n.isShishya"]
                    , "v": version
                });

            }
        });

    });

    //Find user by Last Name
    router.get(BASE_API_URL + '/admin/users/findByFullName', function (req, res) {
        logger.info("Inside Admin findByFullName [GET]");

        var query, uuid, isMobileNumberVerified, userData, props;
        var firstName = req.query['firstName'];
        var lastName = req.query['lastName'];

        logger.debug(req.query);

        query = ["MATCH (n:mUser) WHERE n.firstName = '" + firstName + "' AND n.lastName = '" + lastName + "'"
            + " RETURN n.uuid, n.firstName, n.lastName,n.countryCode,n.mobileNumber,n.isMobileNumberVerified,n.isGuru,n.isShishya"].join('\n');
        logger.debug(query);

        graph.query(query, function (err, results) {
            if (results.length) {
                res.json({
                    "statuscode": 200
                    , "msgkey": "user_details"
                    , "uuid": results[0]["n.uuid"]
                    , "countryCode": results[0]["n.countryCode"]
                    , "mobileNumber": results[0]["n.mobileNumber"]
                    , "firstName": results[0]["n.firstName"]
                    , "lastName": results[0]["n.lastName"]
                    , "isMobileNumberVerified": results[0]["n.isMobileNumberVerified"]
                    , "isGuru": results[0]["n.isGuru"]
                    , "isShishya": results[0]["n.isShishya"]
                    , "v": version
                });

            }
        });

    });


    //List Guru details
    router.get(BASE_API_URL + '/admin/users/gurus', function (req, res) {
        logger.info("Inside Admin gurus [GET]");

        var countryCode = req.query['countryCode'];
        var mobileNumber = req.query['mobileNumber'];

        query = ["MATCH (s:mUser) WHERE s.countryCode = " + countryCode + " AND s.mobileNumber='" + mobileNumber + "'"
            + "MATCH (g) - [r:IS_GURU_OF] ->(s) "
            + " WHERE r.status <> '2' "
            + "RETURN r.status as status, g.firstName as firstName, g.lastName as lastName, g.uuid as uuid, g.countryCode as countryCode, g.mobileNumber as mobileNumber"].join('\n');
        console.log(query);

        graph.query(query, function (err, results) {
            console.log("results"); console.log(results);

            //Step 3: If IS_GURU_OF relation found
            if (results.length) {

                res.json({
                    "statuscode": 200
                    , "msgkey": "get_guru_success"
                    , "gurus": results
                    , "v": version
                });

            }//end: if (results.length) { If IS_GURU_OF relation is present
            else {// guru array empty
                res.json({
                    "statuscode": 200
                    , "msgkey": "get_guru_success"
                    , "gurus": results
                    , "v": version
                });

            } //end :guru array empty

        });

    });

    //List Shishya details
    router.get(BASE_API_URL + '/admin/users/shishyas', function (req, res) {
        logger.info("Inside Admin shishyas [GET]");

        var countryCode = req.query['countryCode'];
        var mobileNumber = req.query['mobileNumber'];

        query = ["MATCH (g:mUser) WHERE g.countryCode = " + countryCode + " AND g.mobileNumber='" + mobileNumber + "'"
            + "MATCH (g) - [r:IS_GURU_OF] ->(s) "
            + " WHERE r.status <> '2' "
            + "RETURN r.status as status, s.firstName as firstName, s.lastName as lastName, s.uuid as uuid, s.countryCode as countryCode, s.mobileNumber as mobileNumber"].join('\n');
        console.log(query);

        graph.query(query, function (err, results) {
            console.log("results"); console.log(results);
            if (results.length) {
                res.json({
                    "statuscode": 200
                    , "msgkey": "get_shishya_success"
                    , "gurus": results
                    , "v": version
                });
            }
            else {
                res.json({
                    "statuscode": 200
                    , "msgkey": "get_shishya_success"
                    , "gurus": results
                    , "v": version
                });

            }
        });
    });

    router.put(BASE_API_URL + '/admin/users/:id/isApproved', function (req, res) {
        logger.info("Inside Admin isApproved [PUT]");

        var uuid = req.params['id'];
        var isGuru = req.query['isGuru'];
        var isShishya = req.query['isShishya'];

        console.log(req.params);
        console.log(req.query);

        if (req.query.isGuru == "true") {
            isGuru = true;
        }
        if (req.query.isShishya == "true") {
            isShishya = true;
        }

        if (isGuru == true) {
            query = ["MATCH (g) "
                + "WHERE g.uuid='" + uuid + "' "
                + "SET g.isGuruApproved=true "
                + "RETURN g"].join('\n');
        }
        else if (isShishya == true) {
            query = ["MATCH (s) "
                + "WHERE s.uuid='" + uuid + "' "
                + "SET s.isShishyaApproved=true "
                + "RETURN s"].join('\n');
        }

        console.log("query"); console.log(query);
        graph.query(query, function (err, results) {
            console.log("results: "); console.log(results);
            res.json({
                "statuscode": 200
                , "msgkey": "approved.success"
                , "v": version
            });
        });
    });

















    /********************Sign up post call 1****************/
    router.post(BASE_API_URL + '/users/signup1', function (req, res) {

        //Local Variable Declarations
        var opentokSessionId, generateOTToken;
        var query;


        //STEP 1: Parse the Request Parameters
        var countryCode = req.body.countryCode;
        var mobileNumber = req.body.mobileNumber;
        var isGuru = req.body.isGuru;
        var isShishya = req.body.isShishya;
        var isVerificationRequested = req.body.isVerificationRequested;

        //STEP 2: Check for the existence of the user and the mobile number verification status
        var data = {
            "countryCode": countryCode
            , "mobileNumber": mobileNumber
        };
        sendOTP.checkUserNameExistCall(data, function (checkUserNameExistCallResult) {

            console.log("checkUserNameExistCallResult"); console.log(checkUserNameExistCallResult);

            //STEP 3: Create mUser Node, if the user does not exist
            if (checkUserNameExistCallResult.msgkey == "user does not found") {

                //3.a Prepare the properties that are common to both Guru and Shishya    
                var data = {
                    "countryCode": countryCode
                    , "mobileNumber": mobileNumber
                };

                if (isShishya) {
                    data["isShishya"] = true;
                }


                //3b. Set the properties that are unique to Guru  and Shishya
                if (isGuru) {
                    data["isGuru"] = true;
                    sendOTP.opentokSessionIdCall(function (opentokSessionIdCallResult) {
                        console.log("opentokSessionIdCallResult"); console.log(opentokSessionIdCallResult);
                        data["opentokSessionId"] = opentokSessionIdCallResult.opentokSessionId;;


                    }); //end: sendOTP.opentokSessionIdCall(function (opentokSessionIdCallResult) {

                }


            } //end: if (checkUserNameExistCallResult.msgkey == "user does not found") {




        }); //end: sendOTP.checkUserNameExistCall(data, function (checkUserNameExistCallResult) {

    }); //end: router.post(BASE_API_URL + '/users/signup1', function (req, res) {
    /********************Sign up post call 1****************/


    /********************Sign up post call 2****************/

    router.post(BASE_API_URL + '/users/signup2', function (req, res) {

        var countryCode = req.body.countryCode;
        var mobileNumber = req.body.mobileNumber;
        var userName = countryCode + mobileNumber;

        var oneTimePassword = req.body.oneTimePassword;
        //call msg91 verifyOTP
        //if(successfull && VerifiedUser=true) then Update lastOTPVarificationDate=todaysDate
        //send opentok credentials
        //send uuid
        //& send passportLoginSessionId
        //else send error in OTP process/ wrongOTP
        var data = {
            "countryCode": countryCode,
            "mobileNumber": mobileNumber,
            "oneTimePassword": oneTimePassword
        };

        sendOTP.verifyOTPCall(data, function (verifyOTPCallResult) {
            console.log("verifyOTPCallResult");
            console.log(verifyOTPCallResult);
            //change error to success
            if (verifyOTPCallResult.status == "error") {
                console.log("inside if sucess function");
                if (graph != null) {
                    var query;
                    query = ["MATCH (n:mUser) WHERE n.userName='" + userName + "'SET n.lastOTPVarificationDate='0/0/0',n.isMobileNumberVerified=true RETURN n.uuid,n.opentokSessionId"].join('\n');
                    console.log(query);

                    graph.query(query, function (err, results) {
                        if (results.length) {
                            console.log("query success");
                            var uuid = results[0]["n.uuid"];
                            var opentokSessionId = results[0]["n.opentokSessionId"];
                            console.log("uuid " + uuid);
                            console.log("opentokSessionId " + opentokSessionId);
                            var opentokToken;
                            opentokToken = opentok.generateToken(opentokSessionId, {
                                role: "moderator",
                                expireTime: (new Date().getTime() / 1000) + (1 * 24 * 60 * 60)
                            });
                            console.log("opentokToken  " + opentokToken);

                            var token = jwt.sign(userName, "!@OlaHivemSangeet@!");
                            console.log("token " + token);
                            res.json({
                                "statuscode": "200"
                                , "msgkey": "login.success"
                                , "token": token
                                , "opentokToken": opentokToken
                                , "uuid": uuid
                                , "v": version
                            });

                        }
                        else {
                            console.log("query failed");
                            res.json({
                                "statuscode": "300"
                                , "msgkey": "querry failed"
                                , "v": version
                            });
                        }
                    });
                }

            } else

                res.json({
                    "status": verifyOTPCallResult.status
                    , "msgkey": verifyOTPCallResult.msgkey
                    , "v": verifyOTPCallResult.v
                });

        });

        //
    });
    /********************END Sign up post call 2****************/



    // login GET Starts for mobile
    router.get(BASE_API_URL + '/users/mobile', function (req, res) {
        var countryCode = req.query['countryCode'];
        var phoneNumber = req.query['phoneNumber'];
        var userName = countryCode + phoneNumber;

        neo4j.connect(neo4JUrl, function (err, graph) {
            if (err) {
                res.json({
                    "statuscode": "203"
                    , "msgkey": "dbconnection.failure"
                    , "v": version
                });
            }
            else {
                var query;
                query = ["MATCH (n:mUser) WHERE n.userName = '"
                    + userName + "' RETURN n.phoneNumber,n.countryCode,n.fullName,n.emailId,n.userName,n.isPhoneNumberVerified"].join('\n');
                console.log("query for mobile" + query);
                graph.query(query, function (err, results) {
                    // var result = {"fbusername" : fbusername, "token" :token, "isadmin" : results.isadmin, "ischild" : results.ischild,"account" :"exist" };

                    if (results.length) {
                        res.json({
                            "statuscode": "201"
                            , "msgkey": "verified user"
                            , "v": version
                            , "data": results
                        });

                    }
                    else {
                        res.json({
                            "statuscode": "204"
                            , "msgkey": "user does not found"
                            , "v": version
                        });
                    }
                });
            }
        });
    });
    // Login GET Ends for Mobile



    //Forgot password starts
    router.post(BASE_API_URL + '/users/forgotPassword', function (req, res) {
        var countryCode = req.body.countryCode;
        var phoneNumber = req.body.phoneNumber;
        var userName = countryCode + phoneNumber;
        var refreshToken = req.body.refreshToken;

        var password = createHash(req.body.password);

        var baseUrl = 'https://sendotp.msg91.com/api/checkStatus';

        var Url = baseUrl + "?countryCode=" + countryCode + "&mobileNumber=" + phoneNumber + "&refreshToken=" + refreshToken;

        var headerKeys = {
            'Content-Type': 'application/json'
            , 'application-key': key
        };
        request({
            uri: Url
            , method: "GET"
            , headers: headerKeys
        }, function (error, response, body) {
            var res_data = JSON.parse(body);
            var verifiedUser = res_data.response.code;
            console.log("verifiedUser " + verifiedUser);
            if (verifiedUser == "THIS_NUMBER_IS_VERIFIED") {
                neo4j.connect(neo4JUrl, function (err, graph) {
                    if (err) {
                        res.json({
                            "statuscode": "203"
                            , "msgkey": "dbconnection.failure " + err.message
                            , "v": version
                        });
                    }
                    else {
                        var query;

                        query = ["MATCH (n:mUser) WHERE n.userName='" + userName + "' SET n.password='" + password + "' RETURN n"].join('\n');

                        console.log(query);
                        graph.query(query, function (err, results) {
                            if (results) {
                                res.json({
                                    "statuscode": "207"
                                    , "msgkey": "update.success"
                                    , "v": version
                                });
                            }
                            else {
                                res.json({
                                    "statuscode": "208"
                                    , "msgkey": "update.failure"
                                    , "v": version
                                });
                            }
                        });
                    }
                });
            }
            else {
                res.json({
                    "statuscode": "209"
                    , "msgkey": "verification failed"
                    , "v": version
                });
            }
        });
    });

    //End of forgot password

    // invite user
    router.post(BASE_API_URL + '/invite', function (req, res) {

        var name = req.body.name;
        var countryCode = req.body.countryCode;
        var mobileNumber = req.body.mobileNumber;
        var userName = countryCode + mobileNumber;

        var parameters = {
            "props": {
                "userName": userName
                , "name": name
                , "countryCode": countryCode
                , "mobileNumber": mobileNumber
            }
        };

        var invitePreText = "Hey there..! lets try mSangeet .Please signUp with this " + mobileNumber + " & update number later if you want :)";

        //Use (relationshipId) as relation id find it or return r.uuid after creating relation between
        // var inviteMessage = invitePreText + " www.msangeet.com/invite/" + relationshipId;
        var inviteMessage = invitePreText + " www.msangeet.com/invite/";
        // Set a developer key (_required by Google_; see http://goo.gl/4DvFk for more info.) 
        /*        googl.setKey('AIzaSyCPBWImfBAbU9qmWAYLgiX43TWQPWlImT0');
                // Get currently set developer key 
                googl.getKey();
                // Shorten a long url and output the result 
                googl.shorten('http://www.google.com/')
                    .then(function (shortUrl) {
                        console.log("shortUrl" + shortUrl);
                    })
                    .catch(function (err) {
                        console.error(err.message);
                    });
        */

        //starts check user exists or not!

        neo4j.connect(neo4JUrl, function (err, graph) {
            if (err) {
                res.json({
                    "statuscode": "203"
                    , "msgkey": "dbconnection.failure"
                    , "v": version
                });
            }
            else {
                var query;
                /*      query = ["MATCH (n:mUser) WHERE n.userName = '"
                          + userName + "' RETURN n"].join('\n');*/
                //Say he is current user...// find the current user details by session (isAutonicated)
                query = ["MATCH (n:mUser) WHERE n.userName = '919448505697' RETURN n"].join('\n');
                console.log(query);
                graph.query(query, function (err, results) {
                    if (results.length) {
                        //create only relation 
                        //HAS_INVITED
                        //IS_GURU_OF

                    }
                    else {

                        //user does not exists
                        //create node with props
                        //HAS_INVITED
                        //IS_GURU_OF

                        neo4j.connect(neo4JUrl, function (err, graph) {
                            if (err) {
                                res.json({
                                    "statuscode": "203"
                                    , "msgkey": "dbconnection.failure " + err.message
                                    , "v": version
                                });
                            }
                            else {
                                var query;
                                query = ["CREATE (n:mUser { props }) RETURN n"].join('\n');
                                console.log(query);
                                graph.query(query, parameters, function (err, results) {
                                    if (results.length) {
                                        //now find out the uuid of currently created user
                                        neo4j.connect(neo4JUrl, function (err, graph) {
                                            if (err) {
                                                res.json({
                                                    "statuscode": "203"
                                                    , "msgkey": "dbconnection.failure " + err.message
                                                    , "v": version
                                                });
                                            }
                                            else {
                                                var query;
                                                query = ["MATCH (n:mUser) WHERE n.userName = '" + userName + "' RETURN n.uuid"].join('\n');
                                                console.log(query);
                                                graph.query(query, parameters, function (err, results) {
                                                    if (results.length) {
                                                        console.log(results);


                                                    }
                                                    else {
                                                        res.json({
                                                            "statuscode": "208"
                                                            , "msgkey": "relation.failure"
                                                            , "v": version
                                                        });
                                                    }
                                                });

                                            }
                                        });
                                        //end of current user uuid

                                    }
                                    else {
                                        res.json({
                                            "statuscode": "208"
                                            , "msgkey": "relation.failure"
                                            , "v": version
                                        });
                                    }
                                });

                            }
                        });

                        //end of user creation
                    }
                });
            }
        });

    });



    // end of invite
    //invite id starts
    router.get(BASE_API_URL + '/invite', function (req, res) {
        var inviteId = req.query['inviteId'];
        neo4j.connect(neo4JUrl, function (err, graph) {
            if (err) {
                res.json({
                    "statuscode": "203"
                    , "msgkey": "dbconnection.failure"
                    , "v": version
                });
            }
            else {
                var query;
                query = ["MATCH (n:mUser) WHERE n.inviteId = '"
                    + inviteId + "'  RETURN n"].join('\n');
                //	MATCH (cc: mUser)-[guru]-(c:mUser) WHERE cc.phoneNumber='9448505697' RETURN cc
                console.log("query for find invite id :" + query)
                graph.query(query, function (err, results) {
                    if (results.length) {
                        // results[0]["n.phoneNumber"];
                        console.log("results[0]1st try" + results[0]["n.userName"]);
                        if (results[0]["n.isPhoneNumberVerified"] == true) {
                            res.json({
                                "statuscode": "201"
                                , "msgkey": "verified user"
                                , "v": version
                            });
                        }
                        else {
                            res.json({
                                "statuscode": "202"
                                , "msgkey": "unverified user"
                                , "v": version
                            });
                        }
                    }
                    else {
                        res.json({
                            "statuscode": "204"
                            , "msgkey": "user does not found"
                            , "v": version
                        });
                    }
                });
            }
        });
    });
    //invite id ends
    // Start login simple page
    router.post(BASE_API_URL + '/login2', function (req, res) {
        var countryCode = req.body.countryCode;
        var phoneNumber = req.body.phoneNumber;
        var password = req.body.password;
        neo4j.connect(neo4JUrl, function (err, graph) {
            if (err) {
                res.json({
                    "statuscode": "203"
                    , "msgkey": "dbconnection.failure"
                    , "v": version
                });
            }
            else {
                var query;
                query = ["MATCH (n:mUser) WHERE n.countryCode = '"
                    + countryCode + "' AND n.phoneNumber = '" + phoneNumber
                    + "' RETURN n.password"].join('\n');
                console.log(query);
                graph.query(query, function (err, results) {
                    if (results.length) {
                        // console.log("results" + results[0]["n.password"]);
                        var passwordFilter = results[0]["n.password"]
                        if (isValidPassword(password, passwordFilter)) {
                            var token = jwt.sign(phoneNumber, "!@OlaHivemSangeet@!", {
                                expiresInMinutes: 525600
                                // expires in one year
                            });
                            // "data" : results -consists of password
                            res.json({
                                "statuscode": "210"
                                , "msgkey": "loginUser.success"
                                , "v": version
                                , "token": token
                            });
                        }
                        else {
                            res.json({
                                "statuscode": "213"
                                , "msgkey": "invalid userName or password"
                                , "v": version
                                , "token": token
                            });
                        }
                    }
                    else {
                        res.json({
                            "statuscode": "215"
                            , "msgkey": "login failure"
                            , "v": version
                        });
                    }
                });
            }
        });
    });
    // End of login simple page
    // sign up user exist
    router.get(BASE_API_URL + '/_signupfailure', function (req, res) {
        var reponseJson = {
            "status code": "203"
            , "msgkey": "auth.signup.exist"
            , "v": version
        };
        res.json(reponseJson);
    });
    /*
     * router.post(BASE_API_URL + '/login', passport.authenticate('login', {
     * successRedirect : BASE_API_URL + '/mSangeet/api/v1/home', failureRedirect :
     * BASE_API_URL + '/mSangeet/api/v1/_loginfailure', failureFlash : true }) );
     */
    /* Handle Login POST */
    router.post(BASE_API_URL + '/login', function (req, res, next) {
        console.log('in the login method');
        passport.authenticate('login', function (err, user, info) {
            if (err) {
                console.log("Error 1: ", err);
            }
            else if (info) {
                console.log("User info" + user);
                console.log("Info: ", info);
            }
            else {
                console.log("User Outside");
                console.log(user);
                req.login(user, function (err) {
                    if (err) {
                        console.log("Error 2: ", err);
                        var reponseJson = {
                            "statuscode": "203"
                            , "msgkey": "login.failure"
                            , "v": version
                        };
                        res.json(reponseJson);
                        // res.redirect(BASE_API_URL + '/mSangeet/api/v1/_loginfailure');

                    }
                    else {
                        req.session.passport.user = user;
                        console.log(req.isAuthenticated());
                        if (req.isAuthenticated()) {
                            if (req.user.username) {

                            }
                            console.log("response:");
                            console.log(reponseJson);
                            res.json(reponseJson);
                        }
                        // res.redirect(BASE_API_URL + '/mSangeet/api/v1/home');
                    }
                });
            }
        })(req, res, next);
    });
    /* GET Home Page */
    router.get(BASE_API_URL + '/home', isAuthenticated, function (req, res) {
        console.log("req.user.username=", req.user.username);
        if (req.user.username) {
            var reponseJson = {
                "statuscode": "200"
                , "msgkey": "login.success"
                , "token": req.user.token
                , "v": version
                , "data": req.user
            };
        }
        res.json(reponseJson);
    });
    // login failure
    router.get(BASE_API_URL + '/_loginfailure', function (req, res) {
        var reponseJson = {
            "statuscode": "203"
            , "msgkey": "login.failure"
            , "v": version
        };
        res.json(reponseJson);
    });
    /* Handle Logout */
    router.get(BASE_API_URL + '/logout', function (req, res) {
        req.session.destroy(function (err) {
            var reponseJson = {
                "status code": "200"
                , "msgkey": "logout.success"
                , "v": version
            };
            res.json(reponseJson);
        });
    });
    /* Handle Registration POST */
    router.post('/signup', passport.authenticate('signup', {
        successRedirect: BASE_API_URL + '/mSangeet/api/v1/_signupsuccess'
        , failureRedirect: BASE_API_URL + '/mSangeet/api/v1/_signupfailure'
    }));
    /* signup success page */
    router.get(BASE_API_URL + '/_signupsuccess', function (req, res) {
        var reponseJson = {
            "status code": "200"
            , "msgkey": "auth.signup.success"
            , "username": req.user.username
            , "v": version
        };
        // res.render('home', { user: req.user });
        req.logout();
        res.json(reponseJson);
    });
    /* Handle create mUser */
    router.post(BASE_API_URL + '/createmUser', isAuthenticatedAccessToken, function (req, res) {
        var date = new Date();
        var password = createHash(req.body.password);
        var parameters = {
            "props": {
                "firstname": req.body.fname
                , "lastname": req.body.lname
                , "salutation": req.body.salutation
                , "profilepic": req.body.profilepic
                , "dob": req.body.dob
                , "email": req.body.email
                , "altemail": req.body.altemail
                , "phone": req.body.phone
                , "zipcode": req.body.zipcode
                , "area": req.body.area
                , "genres": req.body.genres
                , "forms": req.body.forms
                , "about": req.body.about
                , "israsika": req.body.israsika
                , "isshishya": req.body.isshishya
                , "isguru": req.body.isguru
                , "iskalavida": req.body.iskalavida
                , "issanghataka": req.body.issanghataka
                , "isvidwan": req.body.isvidwan
                , "issamyojak": req.body.issamyojak
                , "isgeetkar": req.body.isgeetkar
                , "istantrajn": req.body.istantrajn
                , "fbusername": req.body.fbusername
                , "fbobjectid": req.body.fbobjid
                , "isadmin": req.body.isadmin
                , "ischild": req.body.ischild
                , "parentid": req.body.parentid
                , "username": req.body.username
                , "password": password
                , "lastupdated": date.toUTCString()
            }
        };
        neo4j.connect(neo4JUrl, function (err, graph) {
            if (err) {
                res.json({
                    "statuscode": "204"
                    , "msgkey": "dbconnection.failure"
                    , "v": version
                });
            }
            else {
                var query;
                query = 'CREATE (n:mUser { props }) RETURN n';
                graph.query(query, parameters, function (err, results) {
                    if (results) {
                        res.json({
                            "statuscode": "200"
                            , "msgkey": "createmUser.success"
                            , "v": version
                        });
                    }
                    else {
                        res.json({
                            "statuscode": "203"
                            , "msgkey": "createmUser.failure"
                            , "v": version
                        });
                    }
                });
            }
        });
    });
    /* Handles update mUser */
    router.post(BASE_API_URL + '/updatemUser', isAuthenticatedAccessToken, function (req, res) {
        var date = new Date();
        var password = createHash(req.body.password);
        var muserid = req.body.id;
        var parameters = {
            "props": {
                "firstname": req.body.fname
                , "lastname": req.body.lname
                , "salutation": req.body.salutation
                , "profilepic": req.body.profilepic
                , "dob": req.body.dob
                , "email": req.body.email
                , "altemail": req.body.altemail
                , "phone": req.body.phone
                , "zipcode": req.body.zipcode
                , "area": req.body.area
                , "genres": req.body.genres
                , "forms": req.body.forms
                , "about": req.body.about
                , "israsika": req.body.israsika
                , "isshishya": req.body.isshishya
                , "isguru": req.body.isguru
                , "iskalavida": req.body.iskalavida
                , "issanghataka": req.body.issanghataka
                , "isvidwan": req.body.isvidwan
                , "issamyojak": req.body.issamyojak
                , "isgeetkar": req.body.isgeetkar
                , "istantrajn": req.body.istantrajn
                , "fbusername": req.body.fbusername
                , "fbobjectid": req.body.fbobjid
                , "isadmin": req.body.isadmin
                , "ischild": req.body.ischild
                , "parentid": req.body.parentid
                , "username": req.body.username
                , "password": password
                , "lastupdated": date.toUTCString()
            }
        };
        if (muserid == 0 || muserid == null) {
            res.json({
                "statuscode": "203"
                , "msgkey": "idmissing.updatemUser.failure"
                , "v": version
            });
        }
        neo4j.connect(neo4JUrl, function (err, graph) {
            if (err) {
                res.json({
                    "statuscode": "203"
                    , "msgkey": "dbconnection.failure"
                    , "v": version
                });
            }
            else {
                var query;
                query = ["MATCH (n:mUser) WHERE ID(n)="
                    + muserid
                    + " SET n = { props } RETURN count(n)"].join('\n');
                graph.query(query, parameters, function (err, results) {
                    if (results) {
                        res.json({
                            "statuscode": "200"
                            , "msgkey": "updatemUser.success"
                            , "v": version
                        });
                    }
                    else {
                        res.json({
                            "statuscode": "203"
                            , "msgkey": "idnotmatching.updatemUser.failure"
                            , "v": version
                        });
                    }
                });
            }
        });
    });
    /* Handles get muser by facebook name */
    router.get(BASE_API_URL + '/getUser', isAuthenticatedAccessToken, function (req, res) {
        var retValue;
        var username = req.query['fbusername'];
        neo4j.connect(neo4JUrl, function (err, graph) {
            if (err) {
                res.json({
                    "statuscode": "203"
                    , "msgkey": "dbconnection.failure"
                    , "v": version
                });
            }
            else {
                code
                var query;
                query = ['MATCH (n:mUser) WHERE n.fbusername = "' + username
                    + '" RETURN n'].join('\n');
                console.log(query);
                graph.query(query, null, function (err, results) {
                    console.log(results);
                    if (results) {
                        res.json({
                            "statuscode": "200"
                            , "msgkey": "getUser.success"
                            , "v": version
                            , "data": results
                        });
                    }
                    else {
                        res.json({
                            "statuscode": "203"
                            , "msgkey": "getUser.failure"
                            , "v": version
                        });
                    }
                });
            }
        });
    });
    /* Handle get all mUsers */
    router.get(BASE_API_URL + '/getAllmUsers', isAuthenticatedAccessToken, function (req, res) {
        var retValue;
        neo4j.connect(neo4JUrl, function (err, graph) {
            if (err) {
                res.json({
                    "statuscode": "203"
                    , "msgkey": "dbconnection.failure"
                    , "v": version
                });
            }
            else {
                var query;
                query = ['MATCH (n:mUser) RETURN n'].join('\n');
                graph.query(query, null, function (err, results) {
                    if (results.length) {
                        res.json({
                            "statuscode": "200"
                            , "msgkey": "getAllmUsers.success"
                            , "v": version
                            , "data": results
                        });
                    }
                    else {
                        res.json({
                            "statuscode": "203"
                            , "msgkey": "getAllmUsers.failure"
                            , "v": version
                        });
                    }
                });
            }
        });
    });
    /* Create mOrganization */
    router.post(BASE_API_URL + '/createmOrganization', isAuthenticatedAccessToken, function (req, res) {
        var date = new Date();
        var password = createHash(req.body.password);
        var parameters = {
            "props": {
                "orgname": req.body.orgname
                , "about": req.body.about
                , "profilephoto": req.body.profilephoto
                , "fbpage": req.body.fbpage
                , "parentorgid": req.body.parentorgid
                , "childorgid": req.body.childorgid
                , "genrestaught": req.body.genrestaught
                , "mediumstaught": req.body.mediumstaught
                , "activities": req.body.activities
                , "pincode": req.body.pincode
                , "address": req.body.address
                , "contactnumber": req.body.contactnumber
                , "contactemail": req.body.contactemail
                , "contactperson": req.body.contactperson
                , "albumsreleased": req.body.albumsreleased
                , "bookspublished": req.body.bookspublished
                , "musicfestivalsconducted": req.body.musicfestivalsconducted
                , "awardsoffered": req.body.awardsoffered
                , "lastupdated": date.toUTCString()
            }
        };
        neo4j.connect(neo4JUrl, function (err, graph) {
            if (err) {
                res.json({
                    "statuscode": "204"
                    , "msgkey": "dbconnection.failure"
                    , "v": version
                });
            }
            else {
                var query;
                query = 'CREATE (n:mOrganization { props }) RETURN n';
                graph.query(query, parameters, function (err, results) {
                    if (results) {
                        res.json({
                            "statuscode": "200"
                            , "msgkey": "createmOrganization.success"
                            , "v": version
                        });
                    }
                    else {
                        res.json({
                            "statuscode": "203"
                            , "msgkey": "createmOrganization.failure"
                            , "v": version
                        });
                    }
                });
            }
        });
    });
    /* Handles update mOrganization */
    router.post(BASE_API_URL + '/updatemOrganization', isAuthenticatedAccessToken, function (req, res) {
        var date = new Date();
        var password = createHash(req.body.password);
        var morganizationid = req.body.id;
        var parameters = {
            "props": {
                "orgname": req.body.orgname
                , "about": req.body.about
                , "profilephoto": req.body.profilephoto
                , "fbpage": req.body.fbpage
                , "parentorgid": req.body.parentorgid
                , "childorgid": req.body.childorgid
                , "genrestaught": req.body.genrestaught
                , "mediumstaught": req.body.mediumstaught
                , "activities": req.body.activities
                , "pincode": req.body.pincode
                , "address": req.body.address
                , "contactnumber": req.body.contactnumber
                , "contactemail": req.body.contactemail
                , "contactperson": req.body.contactperson
                , "albumsreleased": req.body.albumsreleased
                , "bookspublished": req.body.bookspublished
                , "musicfestivalsconducted": req.body.musicfestivalsconducted
                , "awardsoffered": req.body.awardsoffered
                , "lastupdated": date.toUTCString()
            }
        };
        if (morganizationid == 0 || morganizationid == null) {
            res.json({
                "statuscode": "203"
                , "msgkey": "idmissing.updatemOrganization.failure"
                , "v": version
            });
        }
        neo4j.connect(neo4JUrl, function (err, graph) {
            if (err) {
                res.json({
                    "statuscode": "204"
                    , "msgkey": "dbconnection.failure"
                    , "v": version
                });
            }
            else {
                var query;
                query = ["MATCH (n:mOrganization) WHERE ID(n)="
                    + morganizationid
                    + " SET n = { props } RETURN count(n)"].join('\n');
                graph.query(query, parameters, function (err, results) {
                    if (results) {
                        res.json({
                            "statuscode": "200"
                            , "msgkey": "updatemOrganization.success"
                            , "v": version
                        });
                    }
                    else {
                        res.json({
                            "statuscode": "203"
                            , "msgkey": "idnotmatching.updatemOrganization.failure"
                            , "v": version
                        });
                    }
                });
            }
        });
    });
    /* Handle get all node */
    router.get(BASE_API_URL + '/getmOrganization', isAuthenticatedAccessToken, function (req, res) {
        var retValue;
        neo4j.connect(neo4JUrl, function (err, graph) {
            if (err) {
                // throw err;
                res.json({
                    "statuscode": "204"
                    , "msgkey": "dbconnection.failure"
                    , "v": version
                });
            }
            else {
                var query;
                var parameters = {
                    "props": {
                        orgname: req.query["orgname"]
                    }
                };
                // console.log(orgname);
                var orgname = req.query["orgname"];
                query = ["MATCH (n:mOrganization) WHERE n.orgname = '"
                    + orgname + "' RETURN n"].join('\n');
                // console.log(query);
                graph.query(query, null, function (err, results) {
                    if (results.length) {
                        res.json({
                            "statuscode": "200"
                            , "msgkey": "getmOrganization.success"
                            , "username": req.body.username
                            , "v": version
                            , "data": results
                        });
                    }
                    else {
                        res.json({
                            "statuscode": "203"
                            , "msgkey": "getmOrganization.failure"
                            , "username": req.body.username
                            , "v": version
                        });
                    }
                });
            }
        });
    });
    /* Handle get all node */
    router.get(BASE_API_URL + '/getAllmOrganizations', isAuthenticatedAccessToken, function (req, res) {
        var retValue;
        neo4j.connect(neo4JUrl, function (err, graph) {
            if (err) {
                // throw err;
                res.json({
                    "statuscode": "204"
                    , "msgkey": "dbconnection.failure"
                    , "v": version
                });
            }
            else {
                var query;
                query = ['MATCH (n:mOrganization) RETURN n'].join('\n');
                graph.query(query, null, function (err, results) {
                    if (results.length) {
                        res.json({
                            "statuscode": "200"
                            , "msgkey": "getAllmOrganizations.success"
                            , "v": version
                            , "data": results
                        });
                    }
                    else {
                        res.json({
                            "statuscode": "203"
                            , "msgkey": "getAllmOrganizations.failure"
                            , "v": version
                        });
                    }
                });
            }
        });
    });
    /* Add Discipleship */
    router.post(BASE_API_URL + '/addDiscipleship', isAuthenticatedAccessToken, function (req, res) {
        console.log(req.body);
        var orgname = req.body.orgname;
        neo4j.connect(neo4JUrl, function (err, graph) {
            if (err) {
                // throw err;
                res.json({
                    "statuscode": "203"
                    , "msgkey": "dbconnection.failure"
                    , "v": version
                });
            }
            else {
                var orgQuery = 'MATCH (n:mOrganization) WHERE n.orgname="' + orgname + '" RETURN n';
                console.log(orgQuery);
                graph.query(orgQuery, function (orgErr, orgResults) {
                    if (orgResults.length !== 0) {
                        var date = new Date();
                        var orgid = req.body.orgname;
                        var guruid = req.body.guruid;
                        var shishyaid = req.body.shishyaid;
                        var type = req.body.type;
                        var parameters = {
                            "props": {
                                "orgid": orgid
                                , "guruid": guruid
                                , "shishyaid": shishyaid
                                , "genreslearnt": req.body.genreslearnt
                                , "mediumslearnt": req.body.mediumslearnt
                                , "fromyear": req.body.fromyear
                                , "toyear": req.body.toyear
                                , "type": req.body.type
                                , "lastupdated": date.toUTCString()
                            }
                        };
                        var disQuery;
                        disQuery = 'CREATE (n:mDiscipleship { props }) RETURN ID(n)';
                        graph.query(disQuery, parameters, function (disErr, disResults) {
                            if (disResults) {
                                res.json({
                                    "statuscode": "200"
                                    , "msgkey": "addDiscipleship.success"
                                    , "v": version
                                    , "res": disResults
                                });
                            }
                            else {
                                res.json({
                                    "statuscode": "203"
                                    , "msgkey": "addDiscipleship.failure"
                                    , "v": version
                                });
                            }
                        });
                    }
                    else {
                        var date = new Date();
                        var orgparameters = {
                            "props": {
                                "orgname": req.body.orgname
                                , "about": req.body.about
                                , "profilephoto": req.body.profilephoto
                                , "fbpage": req.body.fbpage
                                , "parentorgid": req.body.parentorgid
                                , "childorgid": req.body.childorgid
                                , "genrestaught": req.body.genrestaught
                                , "mediumstaught": req.body.mediumstaught
                                , "activities": req.body.activities
                                , "pincode": req.body.pincode
                                , "address": req.body.address
                                , "contactnumber": req.body.contactnumber
                                , "contactemail": req.body.contactemail
                                , "contactperson": req.body.contactperson
                                , "albumsreleased": req.body.albumsreleased
                                , "bookspublished": req.body.bookspublished
                                , "musicfestivalsconducted": req.body.musicfestivalsconducted
                                , "awardsoffered": req.body.awardsoffered
                                , "lastupdated": date.toUTCString()
                            }
                        };
                        var query;
                        query = 'CREATE (n:mOrganization { props }) RETURN n';
                        graph.query(query, orgparameters, function (err, results) {
                            if (results.length !== 0) {
                                ;
                                var orgid = req.body.orgname;
                                var guruid = req.body.guruid;
                                var shishyaid = req.body.shishyaid;
                                var type = req.body.type;
                                var parameters = {
                                    "props": {
                                        "orgid": orgid
                                        , "guruid": guruid
                                        , "shishyaid": shishyaid
                                        , "genreslearnt": req.body.genreslearnt
                                        , "mediumslearnt": req.body.mediumslearnt
                                        , "fromyear": req.body.fromyear
                                        , "toyear": req.body.toyear
                                        , "type": req.body.type
                                        , "lastupdated": date.toUTCString()
                                    }
                                };
                                var disQuery;
                                disQuery = 'CREATE (n:mDiscipleship { props }) RETURN ID(n)';
                                graph.query(disQuery, parameters, function (disErr, disResults) {
                                    if (disResults) {
                                        res.json({
                                            "statuscode": "200"
                                            , "msgkey": "addDiscipleship.success"
                                            , "v": version
                                            , "res": disResults
                                        });
                                    }
                                    else {
                                        res.json({
                                            "statuscode": "203"
                                            , "msgkey": "addDiscipleship.failure"
                                            , "v": version
                                        });
                                    }
                                });
                            }
                            else {
                                res.json({
                                    "statuscode": "203"
                                    , "msgkey": "createmOrganization.failure"
                                    , "v": version
                                });
                            }
                        });
                    }
                });
            }
        });
    });
    /* Update mAdmin */
    router.post(BASE_API_URL + '/updateDiscipleship', isAuthenticatedAccessToken, function (req, res) {
        console.log(req.body);
        var date = new Date();
        var shishyaid = req.body.id;
        var parameters = {
            "props": {
                "orgid": req.body.orgid
                , "guruid": req.body.guruid
                , "genreslearnt": req.body.genreslearnt
                , "mediumslearnt": req.body.mediumslearnt
                , "fromyear": req.body.fromyear
                , "toyear": req.body.toyear
                , "type": req.body.type
                , "shishyaid": req.body.shishyaid
                , "lastupdated": date.toUTCString()
            }
        };
        console.log(parameters);
        if (shishyaid == 0 || shishyaid == null) {
            res.json({
                "statuscode": "203"
                , "msgkey": "idmissing.updateDiscipleship.failure"
                , "v": version
            });
        }
        neo4j.connect(neo4JUrl, function (err, graph) {
            if (err) {
                // throw err;
                res.json({
                    "statuscode": "203"
                    , "msgkey": "dbconnection.failure"
                    , "v": version
                });
            }
            else {
                var query;
                query = ["MATCH (n:mDiscipleship) WHERE ID(n)="
                    + shishyaid
                    + " SET n = { props } RETURN n"].join('\n');
                console.log(query);
                graph.query(query, parameters, function (err, results) {
                    console.log(results);
                    if (results) {
                        res.json({
                            "statuscode": "200"
                            , "msgkey": "updateDiscipleship.success"
                            , "v": version
                        });
                    }
                    else {
                        res.json({
                            "statuscode": "203"
                            , "msgkey": "idnotmatching.updateDiscipleship.failure"
                            , "v": version
                        });
                    }
                });
            }
        });
    });
    /* Handle get all node */
    router.get(BASE_API_URL + '/getDiscipleship', isAuthenticatedAccessToken, function (req, res) {
        var retValue;
        neo4j.connect(neo4JUrl, function (err, graph) {
            if (err) throw err;
            var query;
            // console.log(orgname);
            var shishyaid = req.query["shishyaid"];
            query = ["MATCH (n:mDiscipleship) WHERE n.shishyaid = '"
                + shishyaid + "' RETURN n"].join('\n');
            // console.log(query);
            graph.query(query, null, function (err, results) {
                if (results.length) {
                    res.json({
                        "statuscode": "200"
                        , "msgkey": "getDiscipleship.success"
                        , "username": req.body.username
                        , "v": version
                        , "data": results
                    });
                }
                else {
                    res.json({
                        "statuscode": "203"
                        , "msgkey": "getDiscipleship.failure"
                        , "username": req.body.username
                        , "v": version
                    });
                }
            });
        });
    });
    /* Create mAdmin */
    router.post(BASE_API_URL + '/addArtistry', isAuthenticatedAccessToken, function (req, res) {
        var date = new Date();
        var parameters = {
            "props": {
                "userid": req.body.userid
                , "awardname": req.body.awardname
                , "awardorg": req.body.awardorg
                , "awardyear": req.body.awardyear
                , "type": req.body.trype
                , "lastupdated": date.toUTCString()
            }
        };
        neo4j.connect(neo4JUrl, function (err, graph) {
            if (err) {
                // throw err;
                res.json({
                    "statuscode": "204"
                    , "msgkey": "databaseconnection.failure"
                    , "v": version
                });
            }
            else {
                var query;
                query = 'CREATE (n:mArtistry { props }) RETURN n';
                graph.query(query, parameters, function (err, results) {
                    if (results.length) {
                        res.json({
                            "statuscode": "200"
                            , "msgkey": "addArtistry.success"
                            , "v": version
                        });
                    }
                    else {
                        res.json({
                            "statuscode": "203"
                            , "msgkey": "addArtistry.failure"
                            , "v": version
                        });
                    }
                });
            }
        });
    });
    /* Update mAdmin */
    router.post(BASE_API_URL + '/updateArtistry', isAuthenticatedAccessToken, function (req, res) {
        var date = new Date();
        var userid = req.body.userid;
        var parameters = {
            "props": {
                "userid": req.body.userid
                , "awardname": req.body.awardname
                , "awardorg": req.body.awardorg
                , "awardyear": req.body.awardyear
                , "type": req.body.type
                , "lastupdated": date.toUTCString()
            }
        };
        console.log(parameters);
        if (userid == 0 || userid == null) {
            res.json({
                "statuscode": "203"
                , "msgkey": "idmissing.updateArtistry.failure"
                , "v": version
            });
        }
        neo4j.connect(neo4JUrl, function (err, graph) {
            if (err) {
                // throw err;
                res.json({
                    "statuscode": "203"
                    , "msgkey": "dbconnection.failure"
                    , "v": version
                });
            }
            else {
                var query;
                query = ["MATCH (n:mArtistry) WHERE ID(n)="
                    + userid
                    + " SET n = { props } RETURN n"].join('\n');
                console.log(query);
                graph.query(query, parameters, function (err, results) {
                    console.log(results);
                    if (results) {
                        res.json({
                            "statuscode": "200"
                            , "msgkey": "updateArtistry.success"
                            , "v": version
                        });
                    }
                    else {
                        res.json({
                            "statuscode": "203"
                            , "msgkey": "idnotmatching.updateArtistry.failure"
                            , "v": version
                        });
                    }
                });
            }
        });
    });
    /* Handle get all node */
    router.get(BASE_API_URL + '/getArtistry', isAuthenticatedAccessToken, function (req, res) {
        var retValue;
        neo4j.connect(neo4JUrl, function (err, graph) {
            if (err) throw err;
            var query;
            var userid = req.query["userid"];
            query = ["MATCH (n:mArtistry) WHERE n.userid = '" + userid
                + "' RETURN n"].join('\n');
            graph.query(query, null, function (err, results) {
                if (results.length) {
                    res.json({
                        "statuscode": "200"
                        , "msgkey": "getArtistry.success"
                        , "v": version
                        , "data": results
                    });
                }
                else {
                    res.json({
                        "statuscode": "203"
                        , "msgkey": "getArtistry.failure"
                        , "v": version
                    });
                }
            });
        });
    });
    /* Handle get all node */
    router.get(BASE_API_URL + '/getUserAvailability', isAuthenticatedAccessToken, function (req, res) {
        var retValue;
        neo4j.connect(neo4JUrl, function (err, graph) {
            if (err) {
                // throw err;
                res.json({
                    "statuscode": "204"
                    , "msgkey": "dbconnection.failure"
                    , "v": version
                });
            }
            else {
                var query;
                // console.log(orgname);
                var role = req.query["role"];
                var username = req.query["username"];
                query = ["MATCH (n:" + role + ") WHERE n.username = '"
                    + username + "' RETURN count(n) as usercount"].join('\n');
                // console.log(query);
                graph.query(query, null, function (err, results) {
                    if (results.length) {
                        res.json({
                            "statuscode": "200"
                            , "msgkey": "getUserAvailability.success"
                            , "username": req.body.username
                            , "v": version
                            , "data": results
                        });
                    }
                    else {
                        res.json({
                            "statuscode": "203"
                            , "msgkey": "getUserAvailability.failure"
                            , "username": req.body.username
                            , "v": version
                        });
                    }
                });
            }
        });
    });
    /* Handle get all node */
    router.get(BASE_API_URL + '/checkFBUser', function (req, res) {
        var retValue;
        neo4j.connect(neo4JUrl, function (err, graph) {
            if (err) throw err;
            var query;
            // console.log(orgname);
            var fbusername = req.query["fbusername"];
            query = ["MATCH (n:mUser) WHERE n.fbusername = '" + fbusername
                + "' RETURN n"].join('\n');
            // console.log(query);
            graph.query(query, null, function (err, results) {
                var token = jwt.sign(fbusername, "!@OlaHivemSangeet@!", {
                    expiresInMinutes: 525600
                    // expires in one year
                });
                console.log("res" + results.fbusername);
                if (results.length) {
                    // var result = {"fbusername" : fbusername, "token" :token, "isadmin" : results.isadmin, "ischild" : results.ischild,"account" :"exist" };

                    res.json({
                        "statuscode": "200"
                        , "msgkey": "checkFBUser.success"
                        , "v": version
                        , "token": token
                        , "data": results
                    });
                }
                else {
                    // var result = {"fbusername" : fbusername, "token"  :token,"account" :"notexist" };

                    res.json({
                        "statuscode": "203"
                        , "msgkey": "checkFBUser.failure"
                        , "v": version
                        , "token": token
                    });
                }
            });
        });
    });
    /* Handle Facebook authentication */
    router.post(BASE_API_URL + '/facebook', function (req, res) {
        var fields = ['email', 'first_name', 'last_name'
            , 'locale', 'timezone', 'gender'
            , 'picture.type(large)', 'link', 'updated_time'
            , 'verified', 'location', 'birthday', 'hometown'];
        var accessTokenUrl = 'https://graph.facebook.com/v2.5/oauth/access_token';
        var graphApiUrl = 'https://graph.facebook.com/v2.5/me?fields=' + fields.join(',');
        var params = {
            code: req.body.code
            , client_id: req.body.clientId
            , client_secret: config.FACEBOOK_SECRET
            , redirect_uri: req.body.redirectUri
        };
        // Step 1. Exchange authorization code for access token.
        request.get({
            url: accessTokenUrl
            , qs: params
            , json: true
        }, function (err, response, accessToken) {
            if (response.statusCode !== 200) {
                return res.status(500).send({
                    message: accessToken.error.message
                });
            }
            // Step 2. Retrieve profile information about the current user.

            request.get({
                url: graphApiUrl
                , qs: accessToken
                , json: true
            }, function (err, response, profile) {
                if (response.statusCode !== 200) {
                    return res.status(500).send({
                        message: profile.error.message
                    });
                }
                console.log(profile);
                var date = new Date();
                var parameters = {
                    "props": {
                        "firstname": profile.first_name
                        , "lastname": profile.last_name
                        , "salutation": ""
                        , "profilepic": profile.picture.data.url
                        , "dob": profile.birthday
                        , "email": profile.email
                        , "altemail": ""
                        , "phone": ""
                        , "zipcode": ""
                        , "area": profile.location.name
                        , "genres": ""
                        , "forms": ""
                        , "about": ""
                        , "israsika": ""
                        , "isshishya": ""
                        , "isguru": ""
                        , "iskalavida": ""
                        , "issanghataka": ""
                        , "isvidwan": ""
                        , "issamyojak": ""
                        , "isgeetkar": ""
                        , "istantrajn": ""
                        , "fbusername": profile.id
                        , "fbobjectid": profile.id
                        , "lastupdated": date.toUTCString()
                    }
                };
                neo4j.connect(neo4JUrl, function (err, graph) {
                    if (err) throw err;
                    var query = ""
                        , queryresult = "";
                    var user = "";
                    query = ["MATCH (n:mUser) WHERE n.fbusername = '"
                        + profile.id
                        + "' RETURN n"].join('\n');
                    console.log(query);
                    graph.query(query, null, function (err, results) {
                        console.log("result");
                        console.log(results);
                        console.log(results.length);
                        var token = jwt.sign(profile.id, "!@OlaHivemSangeet@!");
                        if (results.length !== 0) {
                            user = {
                                "statuscode": "200"
                                , "msgkey": "checkFBUser.success"
                                , "v": version
                                , "username": profile.id
                                , "token": token
                                , "data": results
                            };
                            console.log("if");
                            req.user = user;
                            console.log(req.user);
                            if (req.isAuthenticated()) {
                                console.log("Authenticated");
                                if (req.user.username) {
                                    var reponseJson = {
                                        "statuscode": "201"
                                        , "msgkey": "login.success"
                                        , "token": req.user.token
                                        , "v": version
                                        , "data": req.user.data
                                    };
                                }
                                console.log("response json");
                                console.log(reponseJson);
                                res.json(reponseJson);
                            }
                        }
                        else {
                            var query1 = 'CREATE (n:mUser { props }) RETURN n';
                            graph.query(query1, parameters, function (err1, results1) {
                                if (results1) {
                                    console.log(query1);
                                    console.log(results1);
                                    user = {
                                        "statuscode": "200"
                                        , "msgkey": "createmUser.success"
                                        , "username": profile.id
                                        , "token": token
                                        , "data": results1
                                    };
                                    console.log("else if");
                                }
                                else {
                                    console.log("else else");
                                    console.log(err);
                                    user = {
                                        "statuscode": "203"
                                        , "msgkey": "createmUser.failure"
                                        , "username": profile.id
                                        , "token": token
                                        , "data": results1
                                    };
                                }
                                req.user = user;
                                console.log(req.user);
                                if (req.isAuthenticated()) {
                                    console.log("Authenticated");
                                    if (req.user.username) {
                                        var reponseJson = {
                                            "statuscode": "200"
                                            , "msgkey": "login.success"
                                            , "token": req.user.token
                                            , "v": version
                                            , "data": req.user.data
                                        };
                                    }
                                    console.log("response json");
                                    console.log(reponseJson);
                                    res.json(reponseJson);
                                }
                            });
                        }
                    });
                });
            });
        });
    });
    /* Create mAdmin */
    router.post(BASE_API_URL + '/addasAdmin', isAuthenticatedAccessToken, function (req, res) {
        neo4j.connect(neo4JUrl, function (err, graph) {
            if (err) {
                // throw err;
                res.json({
                    "statuscode": "204"
                    , "msgkey": "dbconnection.failure"
                    , "v": version
                });
            }
            else {
                var query;
                query = ['MATCH (n:mUser) WHERE n.fbusername = "'
                    + fbusername
                    + '" SET "isadmin" = "true" RETURN n'].join('\n');
                graph.query(query, parameters, function (err, results) {
                    if (results) {
                        res.json({
                            "statuscode": "200"
                            , "msgkey": "addasAdmin.success"
                            , "v": version
                        });
                    }
                    else {
                        res.json({
                            "statuscode": "203"
                            , "msgkey": "addasAdmin.failure"
                            , "v": version
                        });
                    }
                });
            }
        });
    });
    /* Create mAdmin */
    router.post(BASE_API_URL + '/addTutorship', isAuthenticatedAccessToken, function (req, res) {
        var date = new Date();
        var parameters = {
            "props": {
                "userid": req.body.userid
                , "genrestaught": req.body.genrestaught
                , "teachingmedium": req.body.teachingmedium
                , "studentprofileadmitted": req.body.studentprofileadmitted
                , "lastupdated": date.toUTCString()
            }
        };
        neo4j.connect(neo4JUrl, function (err, graph) {
            if (err) {
                // throw err;
                res.json({
                    "statuscode": "204"
                    , "msgkey": "databaseconnection.failure"
                    , "v": version
                });
            }
            else {
                var query;
                query = 'CREATE (n:mTutorship { props }) RETURN n';
                graph.query(query, parameters, function (err, results) {
                    if (results.length) {
                        res.json({
                            "statuscode": "200"
                            , "msgkey": "createTutorship.success"
                            , "v": version
                        });
                    }
                    else {
                        res.json({
                            "statuscode": "203"
                            , "msgkey": "createTutorship.failure"
                            , "v": version
                        });
                    }
                });
            }
        });
    });
    /* Update mAdmin */
    router.post(BASE_API_URL + '/updateTutorship', isAuthenticatedAccessToken, function (req, res) {
        var date = new Date();
        var userid = req.body.userid;
        var parameters = {
            "props": {
                "userid": userid
                , "genrestaught": req.body.genrestaught
                , "teachingmedium": req.body.teachingmedium
                , "studentprofileadmitted": req.body.studentprofileadmitted
                ,
            }
        };
        console.log(parameters);
        if (userid == 0 || userid == null) {
            res.json({
                "statuscode": "203"
                , "msgkey": "idmissing.updateTutorship.failure"
                , "v": version
            });
        }
        neo4j.connect(neo4JUrl, function (err, graph) {
            if (err) {
                // throw err;
                res.json({
                    "statuscode": "203"
                    , "msgkey": "dbconnection.failure"
                    , "v": version
                });
            }
            else {
                var query;
                query = ["MATCH (n:mTutorship) WHERE ID(n)="
                    + userid
                    + " SET n = { props } RETURN n"].join('\n');
                console.log(query);
                graph.query(query, parameters, function (err, results) {
                    console.log(results);
                    if (results) {
                        res.json({
                            "statuscode": "200"
                            , "msgkey": "updateTutorship.success"
                            , "v": version
                        });
                    }
                    else {
                        res.json({
                            "statuscode": "203"
                            , "msgkey": "idnotmatching.updateTutorship.failure"
                            , "v": version
                        });
                    }
                });
            }
        });
    });
    /* Handle get all node */
    router.get(BASE_API_URL + '/getTutorship', isAuthenticatedAccessToken, function (req, res) {
        var retValue;
        neo4j.connect(neo4JUrl, function (err, graph) {
            if (err) throw err;
            var query;
            var userid = req.query["userid"];
            query = ["MATCH (n:mTutorship) WHERE n.userid = '"
                + userid + "' RETURN n"].join('\n');
            graph.query(query, null, function (err, results) {
                if (results.length) {
                    res.json({
                        "statuscode": "200"
                        , "msgkey": "getTutorship.success"
                        , "username": req.body.username
                        , "v": version
                        , "data": results
                    });
                }
                else {
                    res.json({
                        "statuscode": "203"
                        , "msgkey": "getTutorship.failure"
                        , "username": req.body.username
                        , "v": version
                    });
                }
            });
        });
    });
    /* Create mGenres */
    router.post(BASE_API_URL + '/addGenres', isAuthenticatedAccessToken, function (req, res) {
        var date = new Date();
        var parameters = {
            "props": {
                "name": req.body.name
                , "isactive": req.body.isactive
                , "lastupdated": date.toUTCString()
            }
        };
        neo4j.connect(neo4JUrl, function (err, graph) {
            if (err) {
                // throw err;
                res.json({
                    "statuscode": "204"
                    , "msgkey": "databaseconnection.failure"
                    , "v": version
                });
            }
            else {
                var query;
                query = 'CREATE (n:mGenres { props }) RETURN n';
                graph.query(query, parameters, function (err, results) {
                    if (results.length) {
                        res.json({
                            "statuscode": "200"
                            , "msgkey": "addGenres.success"
                            , "v": version
                        });
                    }
                    else {
                        res.json({
                            "statuscode": "203"
                            , "msgkey": "addGenres.failure"
                            , "v": version
                        });
                    }
                });
            }
        });
    });
    /* Update mAdmin */
    router.post(BASE_API_URL + '/updateGenres', isAuthenticatedAccessToken, function (req, res) {
        var date = new Date();
        var genresid = req.body.genresid;
        var parameters = {
            "props": {
                "id": genresid
                , "name": req.body.name
                , "isactive": req.body.isactive
                , "lastupdated": date.toUTCString()
            }
        };
        console.log(parameters);
        if (userid == 0 || userid == null) {
            res.json({
                "statuscode": "203"
                , "msgkey": "idmissing.updateGenres.failure"
                , "v": version
            });
        }
        neo4j.connect(neo4JUrl, function (err, graph) {
            if (err) {
                // throw err;
                res.json({
                    "statuscode": "203"
                    , "msgkey": "dbconnection.failure"
                    , "v": version
                });
            }
            else {
                var query;
                query = ["MATCH (n:mGenres) WHERE ID(n)="
                    + userid
                    + " SET n = { props } RETURN n"].join('\n');
                console.log(query);
                graph.query(query, parameters, function (err, results) {
                    console.log(results);
                    if (results) {
                        res.json({
                            "statuscode": "200"
                            , "msgkey": "updateGenres.success"
                            , "v": version
                        });
                    }
                    else {
                        res.json({
                            "statuscode": "203"
                            , "msgkey": "idnotmatching.updateGenres.failure"
                            , "v": version
                        });
                    }
                });
            }
        });
    });
    /* Handle get all node */
    router.get(BASE_API_URL + '/getGenres', isAuthenticatedAccessToken, function (req, res) {
        var retValue;
        neo4j.connect(neo4JUrl, function (err, graph) {
            if (err) {
                // throw err;
                res.json({
                    "statuscode": "204"
                    , "msgkey": "dbconnection.failure"
                    , "v": version
                });
            }
            else {
                var query;
                var genresid = req.query["genresid"];
                query = ["MATCH (n:mGenres) WHERE n.id = '" + genresid
                    + "' RETURN n"].join('\n');
                graph.query(query, null, function (err, results) {
                    if (results.length) {
                        res.json({
                            "statuscode": "200"
                            , "msgkey": "getGenres.success"
                            , "v": version
                            , "data": results
                        });
                    }
                    else {
                        res.json({
                            "statuscode": "203"
                            , "msgkey": "getGenres.failure"
                            , "v": version
                        });
                    }
                });
            }
        });
    });
    /* Handle get all node */
    router.get(BASE_API_URL + '/getAllGenres', isAuthenticatedAccessToken, function (req, res) {
        var retValue;
        neo4j.connect(neo4JUrl, function (err, graph) {
            if (err) {
                // throw err;
                res.json({
                    "statuscode": "204"
                    , "msgkey": "dbconnection.failure"
                    , "v": version
                });
            }
            else {
                var query;
                var genresid = req.query["genresid"];
                query = ["MATCH (n:mGenres) RETURN n"].join('\n');
                graph.query(query, null, function (err, results) {
                    if (results.length) {
                        res.json({
                            "statuscode": "200"
                            , "msgkey": "getAllGenres.success"
                            , "v": version
                            , "data": results
                        });
                    }
                    else {
                        res.json({
                            "statuscode": "203"
                            , "msgkey": "getAllGenres.failure"
                            , "v": version
                        });
                    }
                });
            }
        });
    });
    /* Create mGenres */
    router.post(BASE_API_URL + '/addForms', isAuthenticatedAccessToken, function (req, res) {
        var date = new Date();
        var parameters = {
            "props": {
                "name": req.body.name
                , "isactive": req.body.isactive
                , "lastupdated": date.toUTCString()
            }
        };
        neo4j.connect(neo4JUrl, function (err, graph) {
            if (err) {
                // throw err;
                res.json({
                    "statuscode": "204"
                    , "msgkey": "databaseconnection.failure"
                    , "v": version
                });
            }
            else {
                var query;
                query = 'CREATE (n:mForms { props }) RETURN n';
                graph.query(query, parameters, function (err, results) {
                    if (results.length) {
                        res.json({
                            "statuscode": "200"
                            , "msgkey": "addForms.success"
                            , "v": version
                        });
                    }
                    else {
                        res.json({
                            "statuscode": "203"
                            , "msgkey": "addForms.failure"
                            , "v": version
                        });
                    }
                });
            }
        });
    });
    /* Update mForms */
    router.post(BASE_API_URL + '/updateForms', isAuthenticatedAccessToken, function (req, res) {
        var date = new Date();
        var formsid = req.body.formsid;
        var parameters = {
            "props": {
                "id": formsid
                , "name": req.body.name
                , "isactive": req.body.isactive
                , "lastupdated": date.toUTCString()
            }
        };
        console.log(parameters);
        if (userid == 0 || userid == null) {
            res.json({
                "statuscode": "203"
                , "msgkey": "idmissing.updateForms.failure"
                , "v": version
            });
        }
        neo4j.connect(neo4JUrl, function (err, graph) {
            if (err) {
                // throw err;
                res.json({
                    "statuscode": "203"
                    , "msgkey": "dbconnection.failure"
                    , "v": version
                });
            }
            else {
                var query;
                query = ["MATCH (n:mForms) WHERE ID(n)="
                    + userid
                    + " SET n = { props } RETURN n"].join('\n');
                console.log(query);
                graph.query(query, parameters, function (err, results) {
                    console.log(results);
                    if (results) {
                        res.json({
                            "statuscode": "200"
                            , "msgkey": "updateForms.success"
                            , "v": version
                        });
                    }
                    else {
                        res.json({
                            "statuscode": "203"
                            , "msgkey": "idnotmatching.updateForms.failure"
                            , "v": version
                        });
                    }
                });
            }
        });
    });
    /* Handle get all node */
    router.get(BASE_API_URL + '/getForms', isAuthenticatedAccessToken, function (req, res) {
        var retValue;
        neo4j.connect(neo4JUrl, function (err, graph) {
            if (err) {
                // throw err;
                res.json({
                    "statuscode": "204"
                    , "msgkey": "dbconnection.failure"
                    , "v": version
                });
            }
            else {
                var query;
                var formsid = req.query["formsid"];
                query = ["MATCH (n:mForms) WHERE n.id = '" + formsid
                    + "' RETURN n"].join('\n');
                graph.query(query, null, function (err, results) {
                    if (results.length) {
                        res.json({
                            "statuscode": "200"
                            , "msgkey": "getForms.success"
                            , "v": version
                            , "data": results
                        });
                    }
                    else {
                        res.json({
                            "statuscode": "203"
                            , "msgkey": "getForms.failure"
                            , "v": version
                        });
                    }
                });
            }
        });
    });
    /* Handle get all node */
    router.get(BASE_API_URL + '/getAllForms', isAuthenticatedAccessToken, function (req, res) {
        var retValue;
        neo4j.connect(neo4JUrl, function (err, graph) {
            if (err) {
                // throw err;
                res.json({
                    "statuscode": "204"
                    , "msgkey": "dbconnection.failure"
                    , "v": version
                });
            }
            else {
                var query;
                var genresid = req.query["genresid"];
                query = ["MATCH (n:mForms) RETURN n"].join('\n');
                graph.query(query, null, function (err, results) {
                    if (results.length) {
                        res.json({
                            "statuscode": "200"
                            , "msgkey": "getAllForms.success"
                            , "v": version
                            , "data": results
                        });
                    }
                    else {
                        res.json({
                            "statuscode": "203"
                            , "msgkey": "getAllForms.failure"
                            , "v": version
                        });
                    }
                });
            }
        });
    });
    /* Handle get all node */
    router.get(BASE_API_URL + '/getUserAvailability', isAuthenticatedAccessToken, function (req, res) {
        var retValue;
        neo4j.connect(neo4JUrl, function (err, graph) {
            if (err) {
                // throw err;
                res.json({
                    "statuscode": "204"
                    , "msgkey": "dbconnection.failure"
                    , "v": version
                });
            }
            else {
                var query;
                var username = req.query["username"];
                query = ["MATCH (n:mUser) WHERE n.username = '"
                    + username + "' RETURN count(n) as usercount"].join('\n');
                // console.log(query);
                graph.query(query, null, function (err, results) {
                    if (results.length) {
                        res.json({
                            "statuscode": "200"
                            , "msgkey": "getUserAvailability.success"
                            , "v": version
                            , "data": results
                        });
                    }
                    else {
                        res.json({
                            "statuscode": "203"
                            , "msgkey": "getUserAvailability.failure"
                            , "v": version
                        });
                    }
                });
            }
        });
    });
    /* Handle get all node */
    router.post(BASE_API_URL + '/caLogin', function (req, res) {
        var retValue;
        neo4j.connect(neo4JUrl, function (err, graph) {
            if (err) {
                // throw err;
                res.json({
                    "statuscode": "204"
                    , "msgkey": "dbconnection.failure"
                    , "v": version
                });
            }
            else {
                var query;
                // console.log(orgname);
                var username = req.body.username;
                var password = createHash(req.body.password);
                var query = ["MATCH (n:mUser) WHERE n.username = '" + username
                    + "' AND n.password = '" + password + "' RETURN n"].join('\n');
                // console.log(query);
                graph.query(query, null, function (err, results) {
                    var token = jwt.sign(username, "!@OlaHivemSangeet@!", {
                        expiresInMinutes: 525600
                        // expires in one year
                    });
                    // console.log("res" + results.fbusername);
                    if (results.length) {
                        res.json({
                            "statuscode": "200"
                            , "msgkey": "caLogin.success"
                            , "v": version
                            , "token": token
                            , "data": results
                        });
                    }
                    else {
                        // var result = {"fbusername" : fbusername, "token"
                        // :token,"account" :"notexist" };
                        res.json({
                            "statuscode": "203"
                            , "msgkey": "caLogin.failure"
                            , "v": version
                        });
                    }
                });
            }
        });
    });
    /* Create mGenres */
    router.post(BASE_API_URL + '/createChildParent', isAuthenticatedAccessToken, function (req, res) {
        var date = new Date();
        var parameters = {
            "props": {
                "name": req.body.name
                , "isactive": req.body.isactive
                , "lastupdated": date.toUTCString()
            }
        };
        neo4j.connect(neo4JUrl, function (err, graph) {
            if (err) {
                // throw err;
                res.json({
                    "statuscode": "204"
                    , "msgkey": "databaseconnection.failure"
                    , "v": version
                });
            }
            else {
                var parentid = req.body.parentid;
                var childid = req.body.childid;
                var query;
                query = ["MATCH (child:mUser) WHERE ID(you)= "
                    + parentid
                    + " MATCH  (child:mUser) WHERE ID(child)="
                    + childid
                    + " CREATE (parent)-[parentof:PARENTOF]->(child) RETURN parent,parentof,child"].join('\n');
                graph.query(query, parameters, function (err, results) {
                    console.log("query" + query);
                    console.log("result" + results);
                    if (results.length) {
                        res.json({
                            "statuscode": "200"
                            , "msgkey": "createChildParent.success"
                            , "v": version
                        });
                    }
                    else {
                        res.json({
                            "statuscode": "203"
                            , "msgkey": "createChildParent.failure"
                            , "v": version
                        });
                    }
                });
            }
        });
    });
    /* Create mGenres */
    router.post(BASE_API_URL + '/createStudentTeacher', isAuthenticatedAccessToken, function (req, res) {
        neo4j.connect(neo4JUrl, function (err, graph) {
            if (err) {
                // throw err;
                res.json({
                    "statuscode": "204"
                    , "msgkey": "databaseconnection.failure"
                    , "v": version
                });
            }
            else {
                var studentid = req.body.studentid;
                var teacherid = req.body.teacherid;
                var query;
                query = ["MATCH (student:mUser) WHERE ID(student)= "
                    + studentid
                    + " MATCH  (teacher:mUser) WHERE ID(teacher)="
                    + teacherid
                    + " CREATE (student)-[studentof:STUDENTOF]->(parent) RETURN student,studentof,teacher"].join('\n');
                graph.query(query, parameters, function (err, results) {
                    console.log("query" + query);
                    console.log("result" + results);
                    if (results.length) {
                        res.json({
                            "statuscode": "200"
                            , "msgkey": "createStudentTeacher.success"
                            , "v": version
                        });
                    }
                    else {
                        res.json({
                            "statuscode": "203"
                            , "msgkey": "createStudentTeacher.failure"
                            , "v": version
                        });
                    }
                });
            }
        });
    });
    /* Create mGenres */
    router.post(BASE_API_URL + '/createTeacherOrganization', isAuthenticatedAccessToken, function (req, res) {
        neo4j.connect(neo4JUrl, function (err, graph) {
            if (err) {
                // throw err;
                res.json({
                    "statuscode": "204"
                    , "msgkey": "databaseconnection.failure"
                    , "v": version
                });
            }
            else {
                var teacherid = req.body.teacherid;
                var organizationid = req.body.organizationid;
                var query;
                query = ["MATCH (teacher:mUser) WHERE ID(teacher)= "
                    + teacherid
                    + " MATCH  (organization:mOrganization) WHERE ID(organization)="
                    + organizationid
                    + " CREATE (teacher)-[teacherof:TEACHEROF]->(organization) RETURN teacher,teacherof,organization"].join('\n');
                graph.query(query, parameters, function (err, results) {
                    console.log("query" + query);
                    console.log("result" + results);
                    if (results.length) {
                        res.json({
                            "statuscode": "200"
                            , "msgkey": "createTeacherOrganization.success"
                            , "v": version
                        });
                    }
                    else {
                        res.json({
                            "statuscode": "203"
                            , "msgkey": "createTeacherOrganization.failure"
                            , "v": version
                        });
                    }
                });
            }
        });
    });
    /* Create mGenres */
    router.post(BASE_API_URL + '/createStudentOrganization', isAuthenticatedAccessToken, function (req, res) {
        neo4j.connect(neo4JUrl, function (err, graph) {
            if (err) {
                // throw err;
                res.json({
                    "statuscode": "204"
                    , "msgkey": "databaseconnection.failure"
                    , "v": version
                });
            }
            else {
                var teacherid = req.body.teacherid;
                var organizationid = req.body.organizationid;
                var query;
                query = ["MATCH (student:mUser) WHERE ID(student)= "
                    + studentid
                    + " MATCH  (organization:mOrganization) WHERE ID(organization)="
                    + organizationid
                    + " CREATE (student)-[studentof:STUDENTOF]->(organization) RETURN student,studentof,organization"].join('\n');
                graph.query(query, parameters, function (err, results) {
                    console.log("query" + query);
                    console.log("result" + results);
                    if (results.length) {
                        res.json({
                            "statuscode": "200"
                            , "msgkey": "createStudentOrganization.success"
                            , "v": version
                        });
                    }
                    else {
                        res.json({
                            "statuscode": "203"
                            , "msgkey": "createStudentOrganization.failure"
                            , "v": version
                        });
                    }
                });
            }
        });
    });
    /* Create mGenres */
    router.post(BASE_API_URL + '/sendMessage', isAuthenticatedAccessToken, function (req, res) {
        var date = new Date();
        neo4j.connect(neo4JUrl, function (err, graph) {
            if (err) {
                // throw err;
                res.json({
                    "statuscode": "204"
                    , "msgkey": "databaseconnection.failure"
                    , "v": version
                });
            }
            else {
                var to = req.body.to;
                var from = req.body.from;
                var message = req.body.message;
                var query;
                query = ["MATCH (n:mChatConnections) WHERE ((n.to = '"
                    + to
                    + "' AND n.from = '"
                    + from
                    + "') OR (n.to = '"
                    + from
                    + "' AND n.from = '"
                    + to + "')) RETURN n"].join('\n');
                console.log(query);
                graph.query(query, null, function (err, results) {
                    if (results.length) {
                        console.log("result" + results[0]["n"]["id"]);
                        var parameters = {
                            "props": {
                                "mChatConnectionId": results[0]["n"]["id"]
                                , "message": message
                                , "sentat": date
                            }
                        };
                        query = "CREATE (n:mChatMessages { props }) RETURN n";
                        graph.query(query, parameters, function (err, results) {
                            if (results) { }
                            else { }
                        });
                        res.json({
                            "statuscode": "200"
                            , "msgkey": "sendMessage.success"
                            , "v": version
                        });
                    }
                    else {
                        var parameters = {
                            "props": {
                                "to": req.body.to
                                , "from": req.body.from
                            }
                        };
                        query = "CREATE (n:mChatConnections { props }) RETURN ID(n)";
                        graph.query(query, parameters, function (err, results) {
                            if (results.length) {
                                console.log(results[0]["ID(n)"]);
                                var parameters = {
                                    "props": {
                                        "mChatConnectionId": results[0]["ID(n)"]
                                        , "message": message
                                        , "sentat": date
                                    }
                                };
                                query = "CREATE (n:mChatMessages { props }) RETURN n";
                                console.log("else part" + query);
                                graph.query(query, parameters, function (err, results) {
                                    if (results) { }
                                    else { }
                                });
                            }
                            else { }
                        });
                        res.json({
                            "statuscode": "203"
                            , "msgkey": "sendMessage.failure"
                            , "v": version
                        });
                    }
                });
            }
        });
    });
    /* Handle get all node */
    router.get(BASE_API_URL + '/messages', isAuthenticatedAccessToken, function (req, res) {
        var retValue;
        neo4j.connect(neo4JUrl, function (err, graph) {
            if (err) {
                // throw err;
                res.json({
                    "statuscode": "204"
                    , "msgkey": "dbconnection.failure"
                    , "v": version
                });
            }
            else {
                var query;
                var to = req.query["to"];
                var from = req.query["from"];
                query = ["MATCH (n:mChatConnections) WHERE ((n.to = '"
                    + to
                    + "' AND n.from = '"
                    + from
                    + "') OR (n.to = '"
                    + from
                    + "' AND n.from = '"
                    + to + "')) RETURN n"].join('\n');
                // console.log(query);
                graph.query(query, null, function (err, results) {
                    if (results.length) {
                        console.log(results[0]["n"]["id"]);
                        var mccid = results[0]["n"]["id"];
                        query = ["MATCH (n:mChatMessages) WHERE n.mChatConnectionId = '"
                            + mccid
                            + "' RETURN n"].join('\n');
                        console.log("q" + query);
                        graph.query(query, null, function (err, results) {
                            if (results) {
                                res.json({
                                    "statuscode": "200"
                                    , "msgkey": "messages.success"
                                    , "v": version
                                    , "result": results
                                });
                            }
                            else {
                                res.json({
                                    "statuscode": "203"
                                    , "msgkey": "messages.failure"
                                    , "v": version
                                });
                            }
                        });
                    }
                    else {
                        res.json({
                            "statuscode": "203"
                            , "msgkey": "messages.failure"
                            , "v": version
                        });
                    }
                });
            }
        });
    });
    // MATCH (you:Person)WHERE ID(you)=15
    // MATCH (he:Person) WHERE ID(he)=16
    // CREATE (you)-[like:LIKE]->(he)
    // RETURN you,like,he
    /* Create mGenres */
    router.post(BASE_API_URL + '/updateMobile', isAuthenticatedAccessToken, function (req, res) {
        var otp = Math.floor(Math.random() * (99999 - 10000 + 1)) + 10000;
        var date = new Date();
        console.log("otp" + otp);
        neo4j.connect(neo4JUrl, function (err, graph) {
            if (err) {
                // throw err;
                res.json({
                    "statuscode": "204"
                    , "msgkey": "databaseconnection.failure"
                    , "v": version
                });
            }
            else {
                var userid = req.body.userid;
                var phone = req.body.phone;
                var query;
                query = 'CREATE (n:mMobileAuth { props }) RETURN n';
                var parameters = {
                    "props": {
                        "userid": userid
                        , "phone": phone
                        , "otp": otp
                        , "sentat": date
                    }
                };
                graph.query(query, parameters, function (err, results) {
                    console.log("query" + query);
                    console.log("result" + results);
                    if (results.length) {

                        // setup
                        // e-mail
                        // data
                        // with
                        // unicode
                        // symbols
                        // var
                        // smsOptions
                        // = {
                        // mobiles
                        // :
                        // "919164246551",
                        // //
                        // sender
                        // address
                        // message
                        // :
                        // "OTP
                        // ",
                        // sender
                        // :
                        // 'MSANGT',
                        // route
                        // :
                        // '4',
                        // campaign:
                        // "New
                        // Folder",
                        // authkey
                        // :
                        // '49391A7dKGSELS53f44076'
                        // //49391A7dKGSELS53f44076
                        // };
                        //																			
                        // console.log("sending
                        // SMS
                        // to "+
                        // smsOptions.mobiles);
                        // request({
                        // uri :
                        // "https://control.msg91.com/api/sendhttp.php",
                        // method
                        // :
                        // "POST",
                        // form
                        // :
                        // smsOptions
                        // },
                        // function(error,
                        // response,
                        // body)
                        // {
                        // console.log("response
                        // from
                        // SMS
                        // Provider
                        // is: "
                        // +
                        // body);
                        // });

                        res.json({
                            "statuscode": "200"
                            , "msgkey": "createStudentTeacher.success"
                            , "v": version
                        });
                    }
                    else {
                        res.json({
                            "statuscode": "203"
                            , "msgkey": "createStudentTeacher.failure"
                            , "v": version
                        });
                    }
                });
            }
        });
    });
    router.post(BASE_API_URL + '/verifyMobile', isAuthenticatedAccessToken, function (req, res) {
        var date = new Date();
        neo4j.connect(neo4JUrl, function (err, graph) {
            if (err) {
                // throw err;
                res.json({
                    "statuscode": "204"
                    , "msgkey": "databaseconnection.failure"
                    , "v": version
                });
            }
            else {
                var userid = req.body.userid;
                var phone = req.body.phone;
                var otp = req.body.otp;
                var query = ["MATCH (n:mMobileAuth) WHERE (n.userid = '"
                    + userid
                    + "' AND n.phone ='"
                    + phone
                    + "' AND n.otp="
                    + otp
                    + ") RETURN n"].join('\n');
                console.log("Q" + query);
                graph.query(query, null, function (err, results) {
                    if (results.length) {
                        var query;
                        query = "MATCH (n:mUser) SET n.phone='" + phone + "' WHERE n.id='" + userid + "' RETURN n";
                        graph.query(query, null, function (err, results) {
                            res.json({
                                "statuscode": "200"
                                , "msgkey": "verifyMobile.success"
                                , "v": version
                            });
                        });
                    }
                    else {
                        res.json({
                            "statuscode": "203"
                            , "msgkey": "verifyMobile.failure"
                            , "v": version
                        });
                    }
                });
            }
        });
    });
    /* Create mGenres */
    router.post(BASE_API_URL + '/addLocation', isAuthenticatedAccessToken, function (req, res) {
        var date = new Date();
        var locationof = req.body.locationof; // teacher/organization
        var id = req.body.id;
        var parameters = {
            "props": {
                "locationtype": req.body.locationtype
                , "isprimary": req.body.isprimary
                , "isteachinglocation": req.body.isteachinglocation
                , "isconcertlocation": req.body.isconcertlocation
                , "name": req.body.name
                , "pincode": req.body.pincode
                , "latitude": req.body.latitude
                , "longitude": req.body.longitude
                , "gmapurl": req.body.url
                , "address": req.body.address
                , "city": req.body.city
                , "state": req.body.state
                , "country": req.body.country
                , "lastupdated": date.toUTCString()
            }
        };
        neo4j.connect(neo4JUrl, function (err, graph) {
            if (err) {
                // throw err;
                res.json({
                    "statuscode": "204"
                    , "msgkey": "databaseconnection.failure"
                    , "v": version
                });
            }
            else {
                var query;
                query = ["MATCH (user:"
                    + locationof
                    + ") WHERE ID(user)= "
                    + id
                    + " CREATE (location:mLocation { props }) "
                    + " CREATE (location)-[locationof:LOCATIONOF]->(user) RETURN location,locationof,user"].join('\n');
                console.log(query);
                graph.query(query, parameters, function (err, results) {
                    if (results.length) {
                        res.json({
                            "statuscode": "200"
                            , "msgkey": "addLocation.success"
                            , "v": version
                        });
                    }
                    else {
                        res.json({
                            "statuscode": "203"
                            , "msgkey": "addLocation.failure"
                            , "v": version
                        });
                    }
                });
            }
        });
    });
    /* Update mForms */
    router.post(BASE_API_URL + '/updateLocation', isAuthenticatedAccessToken, function (req, res) {
        var date = new Date();
        var parameters = {
            "props": {
                "id": req.body.id
                , "locationtype": req.body.locationtype
                , "isprimary": req.body.isprimary
                , "isteachinglocation": req.body.isteachinglocation
                , "isconcertlocation": req.body.isconcertlocation
                , "name": req.body.name
                , "pincode": req.body.pincode
                , "latitude": req.body.latitude
                , "longitude": req.body.longitude
                , "gmapurl": req.body.url
                , "address": req.body.address
                , "city": req.body.city
                , "state": req.body.state
                , "country": req / body.country
                , "lastupdated": date.toUTCString()
            }
        };
        console.log(parameters);
        if (userid == 0 || userid == null) {
            res.json({
                "statuscode": "203"
                , "msgkey": "idmissing.updateForms.failure"
                , "v": version
            });
        }
        neo4j.connect(neo4JUrl, function (err, graph) {
            if (err) {
                // throw err;
                res.json({
                    "statuscode": "203"
                    , "msgkey": "dbconnection.failure"
                    , "v": version
                });
            }
            else {
                var query;
                query = ["MATCH (n:mLocation) WHERE ID(n)="
                    + userid
                    + " SET n = { props } RETURN n"].join('\n');
                console.log(query);
                graph.query(query, parameters, function (err, results) {
                    console.log(results);
                    if (results) {
                        res.json({
                            "statuscode": "200"
                            , "msgkey": "updateForms.success"
                            , "v": version
                        });
                    }
                    else {
                        res.json({
                            "statuscode": "203"
                            , "msgkey": "idnotmatching.updateForms.failure"
                            , "v": version
                        });
                    }
                });
            }
        });
    });
    /* Handle get all node */
    router.get(BASE_API_URL + '/getAllLocation', isAuthenticatedAccessToken, function (req, res) {
        var retValue;
        neo4j.connect(neo4JUrl, function (err, graph) {
            if (err) {
                // throw err;
                res.json({
                    "statuscode": "204"
                    , "msgkey": "dbconnection.failure"
                    , "v": version
                });
            }
            else {
                var query;
                var locationof = req.query.locationof; // teacher/organization
                var id = req.query.id;
                query = ["MATCH (n:"
                    + locationof
                    + ") -[rlocationof:LOCATIONOF] - (b) WHERE ID(n)="
                    + id + " RETURN b"].join('\n');
                console.log(query);
                graph.query(query, null, function (err, results) {
                    if (results.length) {
                        res.json({
                            "statuscode": "200"
                            , "msgkey": "getForms.success"
                            , "v": version
                            , "data": results
                        });
                    }
                    else {
                        res.json({
                            "statuscode": "203"
                            , "msgkey": "getForms.failure"
                            , "v": version
                        });
                    }
                });
            }
        });
    });


    // Work in progress
    // router.post( BASE_API_URL + '/addSyllabi',isAuthenticatedAccessToken, function(req, res) {
    // console.log(req.body.parts);
    // var data = req.body.parts;
    // var TicketInfo = { Chapter1 : { Section1: { Subsection1: [{"name":10,"value":12}] },
    // Section2: { Subsection1: [{"name":20,"value":22}] } },Chapter2 : { Section1: {
    // Subsection1: [{"name":100,"value":120}]},Section2: { Subsection1: [{"name":200,"value":220}]} } }		
    // neo4j.connect(neo4JUrl, function(err, graph) { if (err) { throw err;				
    // }else{ var chapterid = ""; var sectionid = ""; var subsectionid=""; var constraintid = "";
    // for(var j in TicketInfo ) {
    // var parameters = ""; console.log("j series " + j); var date = new Date();
    // parameters = { "props" : { "name" : j,"lastupdated" : date.toUTCString()} };console.log(parameters);						
    // query = 'CREATE (n:mChapters { props }) RETURN ID(n) as id'; console.log(query);
    // graph.query(query, parameters, function(err, results) {console.log(results[0].id);
    // chapterid = results[0].id;});					
    // for(var p in TicketInfo[j] )
    // {console.log("p series " + p); var parameters = ""; var date = new Date();
    // parameters = { "props" : { "name" : p, "lastupdated" : date.toUTCString() }};console.log(parameters);					
    // var query;
    // query = 'CREATE (n:mSections { props }) RETURN ID(n) as id';console.log(query);
    // graph.query(query, parameters, function(err, results) {
    // // console.log(results[0].id);
    // sectionid = results[0].id;
    // var query1;
    // query1 = [ "MATCH (a:mChapters) WHERE ID(a)= " + chapterid
    // + " MATCH (b:mSections) WHERE ID(b)=" + sectionid+ " CREATE (a)-[has:HAS]->(b) RETURN a,has,b" ] .join('\n');
    // // console.log(query1);
    // graph.query(query1, null, function(err, results) {										}); });
    // for(var r in TicketInfo[j][p]) {console.log("r series" + r);var parameters = "";
    // var date = new Date();
    // parameters = {
    // "props" : {
    // "name" : r,
    // "lastupdated" : date.toUTCString()} };console.log(parameters);var query;
    // query = 'CREATE (n:mSubsections { props }) RETURN ID(n) as id'; console.log(query);
    // graph.query(query, parameters, function(err, results) {console.log(results[0].id);
    // subsectionid = results[0].id; var query2;
    // query2 = [ "MATCH (a:mSections) WHERE ID(a)= "+ sectionid
    // + " MATCH (b:mSubsections) WHERE ID(b)="+ subsectionid
    // + " CREATE (a)-[has:HAS]->(b) RETURN a,has,b" ].join('\n');console.log(query2);
    // graph.query(query2, null, function(err, results) { });});				    		
    // for(var i = 0; i < TicketInfo[j][p][r].length; i++ ){console.log("i series " + TicketInfo[j][p][r][i].name + " == "+
    // TicketInfo[j][p][r][i].value);var parameters = "";parameters = {"props" : {
    // "name" : TicketInfo[j][p][r][i].name,"value": TicketInfo[j][p][r][i].value,
    // "lastupdated" : date.toUTCString()}};console.log(parameters);var query;
    // query = 'CREATE (n:mConstraints { props }) RETURN ID(n) as id';console.log(query);
    // graph.query(query, parameters, function(err, results) {console.log(results[0].id);
    // constraintid = results[0].id;var query3;
    // query3 = [ "MATCH (a:mSubsections) WHERE ID(a)= "
    // + subsectionid
    // + " MATCH (b:mConstraints) WHERE ID(b)="
    // + constraintid
    // + " CREATE (a)-[has:HAS]->(b) RETURN a,has,b" ].join('\n');console.log(query3);
    // graph.query(query3, null, function(err, results) {												});});
    // // console.log(TicketInfo[j][p][i]);}} }} } }); });							
    /* Handle get all node */
    router.get(BASE_API_URL + '/deleteUser', isAuthenticatedAccessToken, function (req, res) {
        var retValue;
        neo4j.connect(neo4JUrl, function (err, graph) {
            if (err) {
                // throw err;
                res.json({
                    "statuscode": "204"
                    , "msgkey": "dbconnection.failure"
                    , "v": version
                });
            }
            else {
                var query;
                var phone = req.query["mobilenumber"];
                query = ["MATCH (n:mChapters) WHERE n.phone=" + phone
                    + " OPTIONAL MATCH (n)-[r]-() DELETE n,r"].join('\n');
                graph.query(query, null, function (err, results) {
                    if (results.length) {
                        res.json({
                            "statuscode": "200"
                            , "msgkey": "deleteUser.success"
                            , "v": version
                            , "data": results
                        });
                    }
                    else {
                        res.json({
                            "statuscode": "203"
                            , "msgkey": "deleteUser.failure"
                            , "v": version
                        });
                    }
                });
            }
        });
    });
    /* Create mGenres */
    router.post(BASE_API_URL + '/addQualification', isAuthenticatedAccessToken, function (req, res) {
        var date = new Date();
        var parameters = {
            "props": {
                "name": req.body.name
                , "isactive": req.body.isactive
                , "lastupdated": date.toUTCString()
            }
        };
        neo4j.connect(neo4JUrl, function (err, graph) {
            if (err) {
                // throw err;
                res.json({
                    "statuscode": "204"
                    , "msgkey": "databaseconnection.failure"
                    , "v": version
                });
            }
            else {
                var query;
                query = 'CREATE (n:mQualification { props }) RETURN n';
                graph.query(query, parameters, function (err, results) {
                    if (results.length) {
                        res.json({
                            "statuscode": "200"
                            , "msgkey": "addQualification.success"
                            , "v": version
                        });
                    }
                    else {
                        res.json({
                            "statuscode": "203"
                            , "msgkey": "addQualification.failure"
                            , "v": version
                        });
                    }
                });
            }
        });
    });
    /* Update mForms */
    router.post(BASE_API_URL + '/updateQualification', isAuthenticatedAccessToken, function (req, res) {
        var date = new Date();
        var qualificationid = req.body.qualificationid;
        var parameters = {
            "props": {
                "id": qualificationid
                , "name": req.body.name
                , "isactive": req.body.isactive
                , "lastupdated": date.toUTCString()
            }
        };
        console.log(parameters);
        if (userid == 0 || userid == null) {
            res.json({
                "statuscode": "203"
                , "msgkey": "idmissing.updateQualification.failure"
                , "v": version
            });
        }
        neo4j.connect(neo4JUrl, function (err, graph) {
            if (err) {
                // throw err;
                res.json({
                    "statuscode": "203"
                    , "msgkey": "dbconnection.failure"
                    , "v": version
                });
            }
            else {
                var query;
                query = ["MATCH (n:mQualification) WHERE ID(n)="
                    + qualificationid
                    + " SET n = { props } RETURN n"].join('\n');
                console.log(query);
                graph.query(query, parameters, function (err, results) {
                    console.log(results);
                    if (results) {
                        res.json({
                            "statuscode": "200"
                            , "msgkey": "updateQualification.success"
                            , "v": version
                        });
                    }
                    else {
                        res.json({
                            "statuscode": "203"
                            , "msgkey": "idnotmatching.updateQualification.failure"
                            , "v": version
                        });
                    }
                });
            }
        });
    });
    /* Handle get all node */
    router.get(BASE_API_URL + '/getQualification', isAuthenticatedAccessToken, function (req, res) {
        var retValue;
        neo4j.connect(neo4JUrl, function (err, graph) {
            if (err) {
                // throw err;
                res.json({
                    "statuscode": "204"
                    , "msgkey": "dbconnection.failure"
                    , "v": version
                });
            }
            else {
                var query;
                var qualificationid = req.query["qualificationid"];
                query = ["MATCH (n:mQualification) WHERE n.id = '"
                    + qualificationid + "' RETURN n"].join('\n');
                graph.query(query, null, function (err, results) {
                    if (results.length) {
                        res.json({
                            "statuscode": "200"
                            , "msgkey": "getQualification.success"
                            , "v": version
                            , "data": results
                        });
                    }
                    else {
                        res.json({
                            "statuscode": "203"
                            , "msgkey": "getQualification.failure"
                            , "v": version
                        });
                    }
                });
            }
        });
    });
    /* Handle get all node */
    router.get(BASE_API_URL + '/getAllQualifications', isAuthenticatedAccessToken, function (req, res) {
        var retValue;
        neo4j.connect(neo4JUrl, function (err, graph) {
            if (err) {
                // throw err;
                res.json({
                    "statuscode": "204"
                    , "msgkey": "dbconnection.failure"
                    , "v": version
                });
            }
            else {
                var query;
                query = ["MATCH (n:mForms) RETURN n"].join('\n');
                graph.query(query, null, function (err, results) {
                    if (results.length) {
                        res.json({
                            "statuscode": "200"
                            , "msgkey": "getAllQualification.success"
                            , "v": version
                            , "data": results
                        });
                    }
                    else {
                        res.json({
                            "statuscode": "203"
                            , "msgkey": "getAllQualification.failure"
                            , "v": version
                        });
                    }
                });
            }
        });
    });
    /* Handle get all node */
    router.get(BASE_API_URL + '/searchByPhone', isAuthenticatedAccessToken, function (req, res) {
        var retValue;
        neo4j.connect(neo4JUrl, function (err, graph) {
            if (err) {
                // throw err;
                res.json({
                    "statuscode": "204"
                    , "msgkey": "dbconnection.failure"
                    , "v": version
                });
            }
            else {
                var query;
                var phone = req.query["phone"];
                query = ["MATCH (n:mUser) WHERE n.phone=" + phone
                    + " RETURN n"].join('\n');
                graph.query(query, null, function (err, results) {
                    if (results.length) {
                        res.json({
                            "statuscode": "200"
                            , "msgkey": "searchByPhone.success"
                            , "v": version
                            , "data": results
                        });
                    }
                    else {
                        res.json({
                            "statuscode": "203"
                            , "msgkey": "searchByPhone.failure"
                            , "v": version
                        });
                    }
                });
            }
        });
    });
    /* Handle get all node */
    router.get(BASE_API_URL + '/autosuggest', isAuthenticatedAccessToken, function (req, res) {
        var retValue;
        var query = "";
        var content = req.query["content"];
        var suggetiontpye = req.query["suggetiontpye"];
        if (suggetiontpye == "organization") {
            query = ["MATCH (n:mOrganization) WHERE n.name=~"
                + content + " RETURN n.name,ID(n) AS id"].join('\n');
        }
        else if (suggetiontpye == "user") {
            query = ["MATCH (n:mUser) WHERE n.name=~" + content
                + " RETURN n.name,ID(n) AS id"].join('\n');
        }
        neo4j.connect(neo4JUrl, function (err, graph) {
            if (err) {
                // throw err;
                res.json({
                    "statuscode": "204"
                    , "msgkey": "dbconnection.failure"
                    , "v": version
                });
            }
            else {
                graph.query(query, null, function (err, results) {
                    if (results.length) {
                        res.json({
                            "statuscode": "200"
                            , "msgkey": "autosuggest.success"
                            , "v": version
                            , "data": results
                        });
                    }
                    else {
                        res.json({
                            "statuscode": "203"
                            , "msgkey": "autosuggest.failure"
                            , "v": version
                        });
                    }
                });
            }
        });
    });
    /* Create mGenres */
    router.post(BASE_API_URL + '/inviteUser', isAuthenticatedAccessToken, function (req, res) {
        var phone = req.body.phone;
        phone = phone.replace('+', '');
        // setup e-mail data with unicode symbols
        var smsOptions = {
            mobiles: phone, // sender address
            message: "OTP "
            , sender: 'GURUSG'
            , route: '4'
            , campaign: "New Folder"
            , authkey: '116236Ae4ugsIj8576e6537'
        };
        console.log("sending SMS to " + smsOptions.mobiles);
        request({
            uri: "https://control.msg91.com/api/sendhttp.php"
            , method: "POST"
            , form: smsOptions
        }, function (error, response, body) {
            if (body != null) {
                res.json({
                    "statuscode": "200"
                    , "msgkey": "inviteUser.success"
                    , "v": version
                });
            }
            else {
                res.json({
                    "statuscode": "203"
                    , "msgkey": "inviteUser.failure"
                    , "v": version
                });
            }
        });
    });
    return router;
}