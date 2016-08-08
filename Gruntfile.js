/**
 * Grunt Uploader for Lambda scripts
 * @author: Chris Moyer <cmoyer@aci.info>
 */
'use strict';
module.exports = function(grunt) {
  require('load-grunt-tasks')(grunt);

  var path = require('path');

  var config = {'functions' : {} };
  try {
    config = require('./resources.conf.json');
  } catch (e) {
  }

  grunt.initConfig({
    lambda_invoke: {
    },
    lambda_deploy: {
      rotateCertificates : {
        package: 'certificatemanager',
        options: {
          file_name: 'index.js',
          handler: 'index.rotateCertificates',
          region: config.region,
        },
        function: config.functions['rotateCertificates'] || 'rotateCertificates',
        arn: null,
      },
      updateCertificates: {
        package: 'certificatemanager',
        options: {
          file_name: 'index.js',
          handler: 'index.updateCertificates',
          region: config.region,
        },
        function: config.functions['updateCertificates'] || 'updateCertificates',
        arn: null,
      }
    },
    lambda_package: {
      rotateCertificates: {
        package: 'certificatemanager',
      },
      updateCertificates: {
        package: 'certificatemanager',
      }
    },
    env: {
      prod: {
        NODE_ENV: 'production',
      },
    },

  });

  grunt.registerTask('deploy', ['env:prod', 'lambda_package', 'lambda_deploy']);
  grunt.registerTask('deploy:rotateCertificates', ['env:prod', 'lambda_package:rotateCertificates', 'lambda_deploy:rotateCertificates']);
  grunt.registerTask('deploy:updateCertificates', ['env:prod', 'lambda_package:updateCertificates', 'lambda_deploy:updateCertificates']);
  grunt.registerTask('test', ['lambda_invoke']);
};
