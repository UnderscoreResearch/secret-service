'use strict';

const supertest = require('supertest');
const test = require('unit.js');
const app = require('../src/app.js');

const request = supertest(app);

describe('Secret Service app', function() {
  it('verifies get', function(done) {
    request.get('/').expect(200).end(function(err, result) {
      test.value(result.body.info.title).contains('Your Shared Secret API');
      test.value(result["body"]["paths"]["/"]["get"]).hasNotProperty("x-amazon-apigateway-integration");
      test.value(result).hasHeader('content-type', 'application/json; charset=utf-8');
      test.value(result).hasHeader("Access-Control-Allow-Origin",'*');
      done(err);
    });
  });
  
  it('verified serviceTime', function(done) {
    request.get('/servicetime').expect(200).end(function(err, result) {
      if (!result.body.serviceTime) {
        done("Missing timme");
        return;
      }
      if (Math.abs(result.body.serviceTime - Date.now()) > 1000) {
        done(result.body.serviceTime - Date.now());
        return;
      }
      done(err);
    });
  });
});
