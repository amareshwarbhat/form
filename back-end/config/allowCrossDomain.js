module.exports =  function(req, res, next) {
	  res.header("Access-Control-Allow-Origin", "http://localhost:7300");
        res.header("Access-Control-Allow-Headers", "X-Requested-With");
        res.header("Access-Control-Allow-Methods", "GET, POST", "PUT", "DELETE");
         // next();

	    if ('OPTIONS' == req.method) {
	        res.sendStatus(200).end();
	    }
	    else {
	        next();
	    }
	};
