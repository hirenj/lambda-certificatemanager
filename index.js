// Get the functions : loginhandler - needs the pubkeys for self and other handlers / datahandler - needs the public key  / exchangetoken - needs the private key for signing sessions
'use strict';
/*jshint esversion: 6, node:true */

/**
 * Lambda function to support JWT.
 * Used for authenticating API requests for API Gateway
 * as a custom authorizer:
 *
 */
const jwkToPem = require('jwk-to-pem');
const pem2jwk = require('pem-jwk').pem2jwk
const fs = require('fs');
const AWS = require('lambda-helpers').AWS;
const temp = require('temp');
const https = require('https');
const JSZip = require('jszip');


let function_locations = {};

let bucket = 'gator';

try {
    let config = require('./resources.conf.json');
    function_locations = config.functions;
    bucket = config.buckets.dataBucket;
} catch (e) {
}

const pubkey_functions = ['loginhandler','datahandler'];
const privkey_functions = ['exchangetoken'];

let generate_signing_key = function() {
  let NodeRSA = require('node-rsa');
  let uuid = require('node-uuid');
  let key_id = uuid.v4();
  let key = new NodeRSA({b: 512 });
  // We should write the pubkey to S3 here too
  let pubkey = key.exportKey('pkcs1-public-pem');
  return {'kid' : key_id, 'public' : pubkey, 'private' : key.exportKey('pkcs1-private-pem')};
};

let retrieve_certs = function(local) {
  let s3 = new AWS.S3();
  let params = {
    Bucket: bucket,
    Key: local ? 'conf/localcerts' : 'conf/authcerts'
  };

  return s3.getObject(params).promise().then(function(result){
    return JSON.parse(result.Body.toString());
  });
};

let write_certs = function(certs,local) {
  let s3 = new AWS.S3();
  let params = {
    Bucket: bucket,
    Body: JSON.stringify(certs),
    Key: local ? 'conf/localcerts' : 'conf/authcerts',
    ACL: 'public-read'
  };
  return s3.putObject(params).promise();
};

let get = function(url,filename) {
  temp.track();
  let output = temp.createWriteStream();
  https.get(url,function(response) {
    response.pipe(output);
  });
  return new Promise(function(resolve,reject) {
    output.on('close',function() {
      resolve(output.path);
    });
    output.on('error',function(err) {
      reject(err);
    });
  });
};

let read_file = function(filename) {
  return new Promise(function(resolve,reject) {
    fs.readFile(filename,function(err,data) {
      if (err) {
        reject(err);
      } else {
        resolve(data);
      }
    });
  });
};

let write_file = function(filename,content) {
  return new Promise(function(resolve,reject) {
    fs.writeFile(filename,content,function(err) {
      if (err) {
        reject(err);
      } else {
        resolve();
      }
    });
  });
};

let get_zipfile = function(filename) {
  return read_file(filename).then((data) => JSZip.loadAsync(data));
};

let rotate_public_keys = function(key) {
  let new_public = pem2jwk(key.public);
  new_public.kid = key.kid;

  // Read local-pubkeys from S3
  return retrieve_certs(true).catch(function(err) {
    if (err.statusCode == 404) {
      return;
    }
    throw err;
  }).then(function(pubkeys) {
    if ( ! pubkeys ) {
      pubkeys = {'keys' : [] };
    }
    console.log("Added in key with kid ",key.kid);
    pubkeys.keys.push(new_public);
    if (pubkeys.keys.length > 10) {
      let removed = pubkeys.keys.splice(0,1);
      console.log("Rotating out key with id ",removed[0].kid);
    }
    return write_certs(pubkeys,true).then( () => pubkeys.keys );
  });
};


let update_function = function(func, content, filename) {
  let lambda = new AWS.Lambda();
  let params = {FunctionName: func };
  lambda.getFunction(params).promise().then(function(result) {
    return get(result.Code.Location);
  }).then(get_zipfile).then(function(zip) {
    zip.file(filename, content);
    return zip.generateAsync({type:"nodebuffer"});
  }).then(function(buffer) {
    params.ZipFile = buffer;
    return lambda.updateFunctionCode(params).promise();
  });
};

let update_function_private_keys = function(privkey) {
  console.log("Deploying private key kid ",privkey.kid);
    return Promise.all(privkey_functions.map((func) => update_function(function_locations[func],JSON.stringify(privkey),'private')));
};

let update_function_public_keys = function(local_keys) {
  return retrieve_certs().then(function(keys) {
    keys.keys = keys.keys.concat(local_keys);
    return keys;
  }).then(function(certs) {
    return Promise.all(pubkey_functions.map((func) => update_function(function_locations[func],JSON.stringify(certs),'public_keys')));
  });
};


let updateFunctions = function() {
  let newkey = generate_signing_key();

  return rotate_public_keys(newkey)
  .then((keyset) => update_function_public_keys(keyset))
  .then( () => console.log("Updated public keys in functions"))
  .then(() => update_function_private_keys(newkey))
  .then( () => console.log("Updated private keys in functions"));
};


updateFunctions().catch(function(err) { console.log(err.stack,err); });