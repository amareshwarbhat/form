define({ "api": [
  {
    "type": "post",
    "url": "/admin/updatebooks",
    "title": "Book Update add/remove handled by admin",
    "version": "0.3.0",
    "name": "PostAdminBookUpdate",
    "group": "Admin_Transaction",
    "permission": [
      {
        "name": "none"
      }
    ],
    "description": "<p>This api will invoked when admin will add/remove the books.</p>",
    "parameter": {
      "fields": {
        "Parameter": [
          {
            "group": "Parameter",
            "type": "bookName",
            "optional": false,
            "field": "String",
            "description": "<p>Book's Book Name</p>"
          }
        ]
      }
    },
    "success": {
      "fields": {
        "Success 200": [
          {
            "group": "Success 200",
            "type": "String",
            "optional": false,
            "field": "_id",
            "description": "<p>Status Code</p>"
          },
          {
            "group": "Success 200",
            "type": "String",
            "optional": false,
            "field": "userName",
            "description": "<p>UserName of user</p>"
          },
          {
            "group": "Success 200",
            "type": "String",
            "optional": false,
            "field": "name",
            "description": "<p>Name of the User</p>"
          },
          {
            "group": "Success 200",
            "type": "String",
            "optional": false,
            "field": "email",
            "description": "<p>Users email</p>"
          },
          {
            "group": "Success 200",
            "type": "String",
            "optional": false,
            "field": "mobileNumber",
            "description": "<p>Users mobileNumber</p>"
          },
          {
            "group": "Success 200",
            "type": "String",
            "optional": false,
            "field": "__v",
            "description": "<p>version</p>"
          },
          {
            "group": "Success 200",
            "type": "String",
            "optional": false,
            "field": "myList",
            "description": "<p>Users List of books</p>"
          }
        ]
      },
      "examples": [
        {
          "title": "Success-Response:",
          "content": " HTTP/1.1 200 OK\n\n\n {\n    \"__v\": 0,\n     \"bookName\": \"c++\",\n     \"bookISBN\": \"IBB001\",\n     \"author\": \"Dennies Richie\",\n     \"bookStatus\": \"book_available\",\n     \"_id\": \"58c6b53d8e7c1a73e343211c\"\n}",
          "type": "json"
        }
      ]
    },
    "error": {
      "fields": {
        "Error 4xx": [
          {
            "group": "Error 4xx",
            "optional": false,
            "field": "Error",
            "description": "<p>in Database</p>"
          }
        ]
      },
      "examples": [
        {
          "title": "Error-Response:",
          "content": "HTTP/1.1 404 Not Found\n{\n   \"statuscode\": 203,\n   \"msgkey\": \"DB_failure\",\n   \"v\": version\n}",
          "type": "json"
        }
      ]
    },
    "filename": "/home/msangeet/Desktop/meanExample/back-end/doc-run/api_server.js",
    "groupTitle": "Admin_Transaction"
  },
  {
    "type": "post",
    "url": "/admin/transaction",
    "title": "Book Transaction handled by admin",
    "version": "0.3.0",
    "name": "PostAdminTransaction",
    "group": "Admin_Transaction",
    "permission": [
      {
        "name": "none"
      }
    ],
    "description": "<p>This api invoked when borrow/return transactions happens.</p>",
    "parameter": {
      "fields": {
        "Parameter": [
          {
            "group": "Parameter",
            "type": "userName",
            "optional": false,
            "field": "String",
            "description": "<p>Users userName</p>"
          }
        ]
      }
    },
    "success": {
      "fields": {
        "Success 200": [
          {
            "group": "Success 200",
            "type": "String",
            "optional": false,
            "field": "_id",
            "description": "<p>Status Code</p>"
          },
          {
            "group": "Success 200",
            "type": "String",
            "optional": false,
            "field": "userName",
            "description": "<p>UserName of user</p>"
          },
          {
            "group": "Success 200",
            "type": "String",
            "optional": false,
            "field": "name",
            "description": "<p>Name of the User</p>"
          },
          {
            "group": "Success 200",
            "type": "String",
            "optional": false,
            "field": "email",
            "description": "<p>Users email</p>"
          },
          {
            "group": "Success 200",
            "type": "String",
            "optional": false,
            "field": "mobileNumber",
            "description": "<p>Users mobileNumber</p>"
          },
          {
            "group": "Success 200",
            "type": "String",
            "optional": false,
            "field": "__v",
            "description": "<p>version</p>"
          },
          {
            "group": "Success 200",
            "type": "String",
            "optional": false,
            "field": "myList",
            "description": "<p>Users List of books</p>"
          }
        ]
      },
      "examples": [
        {
          "title": "Success-Response:",
          "content": "HTTP/1.1 200 OK\n\n{\n  \"_id\": \"58c43ff8eb55c06b6e66e583\",\n  \"userName\": \"amarbhat\",\n  \"name\": \"amar\",\n  \"email\": \"amar@gmail.com\",\n  \"mobileNumber\": \"7829145933\",\n  \"__v\": 0,\n  \"myList\": \"IBB001\"\n}",
          "type": "json"
        }
      ]
    },
    "error": {
      "fields": {
        "Error 4xx": [
          {
            "group": "Error 4xx",
            "optional": false,
            "field": "Error",
            "description": "<p>in Database</p>"
          }
        ]
      },
      "examples": [
        {
          "title": "Error-Response:",
          "content": "HTTP/1.1 404 Not Found\n{\n   \"statuscode\": 203,\n   \"msgkey\": \"DB_failure\",\n   \"v\": version\n}",
          "type": "json"
        }
      ]
    },
    "filename": "/home/msangeet/Desktop/meanExample/back-end/doc-run/api_server.js",
    "groupTitle": "Admin_Transaction"
  },
  {
    "type": "post",
    "url": "/adminUsers",
    "title": "Create admin user",
    "version": "0.3.0",
    "name": "PostAdminUser",
    "group": "Admin_User",
    "permission": [
      {
        "name": "none"
      }
    ],
    "description": "<p>This api will called to create admin user. If the user already exists, then nothing is done</p>",
    "parameter": {
      "fields": {
        "Parameter": [
          {
            "group": "Parameter",
            "type": "userName",
            "optional": false,
            "field": "String",
            "description": "<p>Users userName</p>"
          }
        ]
      }
    },
    "success": {
      "fields": {
        "Success 200": [
          {
            "group": "Success 200",
            "type": "String",
            "optional": false,
            "field": "_id",
            "description": "<p>Status Code</p>"
          },
          {
            "group": "Success 200",
            "type": "String",
            "optional": false,
            "field": "userName",
            "description": "<p>UserName of user</p>"
          },
          {
            "group": "Success 200",
            "type": "String",
            "optional": false,
            "field": "name",
            "description": "<p>Name of the User</p>"
          },
          {
            "group": "Success 200",
            "type": "String",
            "optional": false,
            "field": "email",
            "description": "<p>Users email</p>"
          },
          {
            "group": "Success 200",
            "type": "String",
            "optional": false,
            "field": "v",
            "description": "<p>version</p>"
          }
        ]
      },
      "examples": [
        {
          "title": "Success-Response:",
          "content": "HTTP/1.1 200 OK\n\n{\n  \"__v\": \"0\",\n  \"userName\": \"amarbhat\",\n  \"mobileNumber\": \"7829145933\",\n  \"name\": \"amar\",\n  \"email\": \"amar@gmail.com\",\n  \"_id\": \"58c67e4607113c554ce11cf1\"\n}",
          "type": "json"
        }
      ]
    },
    "error": {
      "fields": {
        "Error 4xx": [
          {
            "group": "Error 4xx",
            "optional": false,
            "field": "Error",
            "description": "<p>in Database</p>"
          }
        ]
      },
      "examples": [
        {
          "title": "Error-Response:",
          "content": "HTTP/1.1 404 Not Found\n{\n   \"statuscode\": 203,\n   \"msgkey\": \"DB_failure\",\n   \"v\": version\n}",
          "type": "json"
        }
      ]
    },
    "filename": "/home/msangeet/Desktop/meanExample/back-end/doc-run/api_server.js",
    "groupTitle": "Admin_User"
  },
  {
    "type": "post",
    "url": "/adminUsers/login",
    "title": "login for Admin User",
    "version": "0.3.0",
    "name": "PostAdminUserLogin",
    "group": "Admin_User",
    "permission": [
      {
        "name": "none"
      }
    ],
    "description": "<p>This api will called to login for Admin user. If login suceessful then send SecToken</p>",
    "parameter": {
      "fields": {
        "Parameter": [
          {
            "group": "Parameter",
            "type": "userName",
            "optional": false,
            "field": "String",
            "description": "<p>Users userName</p>"
          }
        ]
      }
    },
    "success": {
      "fields": {
        "Success 200": [
          {
            "group": "Success 200",
            "type": "String",
            "optional": false,
            "field": "statuscode",
            "description": "<p>Status Code</p>"
          },
          {
            "group": "Success 200",
            "type": "String",
            "optional": false,
            "field": "msgkey",
            "description": "<p>msgkey of user</p>"
          },
          {
            "group": "Success 200",
            "type": "String",
            "optional": false,
            "field": "token",
            "description": "<p>SecToken of the User</p>"
          }
        ]
      },
      "examples": [
        {
          "title": "Success-Response:",
          "content": "HTTP/1.1 200 OK\n\n{\n  \"statuscode\": \"200\",\n  \"msgkey\": \"Login_Success\",\n  \"token\": \"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyTmFtZSI6ImFtYXJiaGF0Iiw\n}",
          "type": "json"
        }
      ]
    },
    "error": {
      "fields": {
        "Error 4xx": [
          {
            "group": "Error 4xx",
            "optional": false,
            "field": "Error",
            "description": "<p>in Database</p>"
          }
        ]
      },
      "examples": [
        {
          "title": "Error-Response:",
          "content": "HTTP/1.1 404 Not Found\n{\n   \"statuscode\": 203,\n   \"msgkey\": \"DB_failure\",\n   \"v\": version\n}",
          "type": "json"
        }
      ]
    },
    "filename": "/home/msangeet/Desktop/meanExample/back-end/doc-run/api_server.js",
    "groupTitle": "Admin_User"
  },
  {
    "type": "get",
    "url": "/users",
    "title": "Retrieve normal user info",
    "version": "0.3.0",
    "name": "GetUser",
    "group": "User",
    "permission": [
      {
        "name": "none"
      }
    ],
    "description": "<p>This api will called to retrieve normal user information. If the user already exists, then nothing is done</p>",
    "parameter": {
      "fields": {
        "Parameter": [
          {
            "group": "Parameter",
            "type": "userName",
            "optional": false,
            "field": "String",
            "description": "<p>Users userName</p>"
          }
        ]
      }
    },
    "success": {
      "fields": {
        "Success 200": [
          {
            "group": "Success 200",
            "type": "String",
            "optional": false,
            "field": "_id",
            "description": "<p>Status Code</p>"
          },
          {
            "group": "Success 200",
            "type": "String",
            "optional": false,
            "field": "userName",
            "description": "<p>UserName of user</p>"
          },
          {
            "group": "Success 200",
            "type": "String",
            "optional": false,
            "field": "name",
            "description": "<p>Name of the User</p>"
          },
          {
            "group": "Success 200",
            "type": "String",
            "optional": false,
            "field": "email",
            "description": "<p>Users email</p>"
          },
          {
            "group": "Success 200",
            "type": "String",
            "optional": false,
            "field": "myList",
            "description": "<p>Users borrowed book details</p>"
          },
          {
            "group": "Success 200",
            "type": "String",
            "optional": false,
            "field": "v",
            "description": "<p>version</p>"
          }
        ]
      },
      "examples": [
        {
          "title": "Success-Response:",
          "content": "    HTTP/1.1 200 OK\n[\n    {\n      \"_id\": \"58c43ff8eb55c06b6e66e583\",\n      \"userName\": \"amarbhat\",\n      \"name\": \"amar\",\n      \"email\": \"amar@gmail.com\",\n      \"mobileNumber\": \"7829145933\",\n      \"__v\": 0,\n      \"myList\": \"IBB001\"\n    }\n]",
          "type": "json"
        }
      ]
    },
    "error": {
      "fields": {
        "Error 4xx": [
          {
            "group": "Error 4xx",
            "optional": false,
            "field": "Error",
            "description": "<p>in Database</p>"
          }
        ]
      },
      "examples": [
        {
          "title": "Error-Response:",
          "content": "HTTP/1.1 404 Not Found\n{\n   \"statuscode\": 203,\n   \"msgkey\": \"DB_failure\",\n   \"v\": version\n}",
          "type": "json"
        }
      ]
    },
    "filename": "/home/msangeet/Desktop/meanExample/back-end/doc-run/api_server.js",
    "groupTitle": "User"
  },
  {
    "type": "post",
    "url": "/users",
    "title": "Create  normal user",
    "version": "0.3.0",
    "name": "PostUser",
    "group": "User",
    "permission": [
      {
        "name": "none"
      }
    ],
    "description": "<p>This api will called to create normal user. If the user already exists, then nothing is done</p>",
    "parameter": {
      "fields": {
        "Parameter": [
          {
            "group": "Parameter",
            "type": "userName",
            "optional": false,
            "field": "String",
            "description": "<p>Users userName</p>"
          }
        ]
      }
    },
    "success": {
      "fields": {
        "Success 200": [
          {
            "group": "Success 200",
            "type": "String",
            "optional": false,
            "field": "_id",
            "description": "<p>Status Code</p>"
          },
          {
            "group": "Success 200",
            "type": "String",
            "optional": false,
            "field": "userName",
            "description": "<p>UserName of user</p>"
          },
          {
            "group": "Success 200",
            "type": "String",
            "optional": false,
            "field": "name",
            "description": "<p>Name of the User</p>"
          },
          {
            "group": "Success 200",
            "type": "String",
            "optional": false,
            "field": "email",
            "description": "<p>Users email</p>"
          },
          {
            "group": "Success 200",
            "type": "String",
            "optional": false,
            "field": "myList",
            "description": "<p>Users borrowed book details</p>"
          },
          {
            "group": "Success 200",
            "type": "String",
            "optional": false,
            "field": "v",
            "description": "<p>version</p>"
          }
        ]
      },
      "examples": [
        {
          "title": "Success-Response:",
          "content": "HTTP/1.1 200 OK\n{\n  \"statuscode\": 200,\n  \"msgkey\": \"username_already_exists\"\n  \"v\": \"1.0\"\n}",
          "type": "json"
        }
      ]
    },
    "error": {
      "fields": {
        "Error 4xx": [
          {
            "group": "Error 4xx",
            "optional": false,
            "field": "Error",
            "description": "<p>in Database</p>"
          }
        ]
      },
      "examples": [
        {
          "title": "Error-Response:",
          "content": "HTTP/1.1 404 Not Found\n{\n   \"statuscode\": 203,\n   \"msgkey\": \"DB_failure\",\n   \"v\": version\n}",
          "type": "json"
        }
      ]
    },
    "filename": "/home/msangeet/Desktop/meanExample/back-end/doc-run/api_server.js",
    "groupTitle": "User"
  }
] });
