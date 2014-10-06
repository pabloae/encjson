	QUnit.module("Unit Testing framework check");
	test("QUnit check", function () {
		ok(1 == "1", "Test passed! (But we didn't actually test anything of EncJson)");
	});

	test("EncJSON setpassword, encrypt and decrypt with test data 1", function (assert) {
		encjson.setpassword('stevenseagal', 1);
		var enc= encjson.encryptjson(testData1);
		var dec= encjson.decryptjson(enc);
		assert.deepEqual(testData1, dec, "Pass! - JSON encrypted and decrypted correctly test data 1");
	});
	test("EncJSON setpassword, encrypt and decrypt with test data 2", function (assert) {
		encjson.setpassword('chucknorris', 1);
		var enc= encjson.encryptjson(testData2);
		var dec= encjson.decryptjson(enc);
		assert.deepEqual(testData2, dec, "Pass! - JSON encrypted and decrypted correctly test data 2");
	});