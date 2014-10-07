encJSON
=======

encJSON - A Javascript library to perform an encryption of a JSON object preserving its structure.

Introduction
----

Sometimes you want to encrypt a JSON object but preserve its structure. For example, when using libraries, such as [TaffyDB], that brings database features to JavaScript applications.

How it works
----

This library encrypts a JSON object using the [Rabbit] stream cipher. The passphrase used for the encryption can be manually set or derivated with the [PBKDF2] key derivation function.

If a key derivation function is used to set the password (recommended). Two 512 bits passphrases will be generated. One passphrase to encrypt the properties and another one to encrypt the values of the JSON.




How to use it
--------------

After including the library this example shows all the functions the encjson object has. You can also check all the QUnit [tests]. 

```javascript
var testData0={ "id": 0, "fact": "Chuck Norris is God"};
//SETTING PASSWORDS
//Option 1: Using a key derivation function with a number of iterations
//In this case 2 iterations with wAlkert3xasrang3r as passphrase
encjson.setpassword('wAlkert3xasrang3r', 2);
//Or with the default nº of iterations: 1000
encjson.setpassword('wAlkert3xasrang3r');
//Option 2: Without a key derivation function
encjson.setrawpassword('wAlkert3xasrang3r');
//Option 3: Set a random password
encjson.setrandompassword();

//ENCRYPTION OF THE JSON
var enc= encjson.encryptjson(testData0);
//DECRYPTION OF THE JSON
var dec= encjson.decryptjson(enc);

//MORE FUNCTIONS
//Individual encryption & decryption of a value
var factEnc= encjson.encryptvalue(testData0['fact']);
var factDec= encjson.decryptvalue(factDec);
//Individual encryption & decryption of a property
var factEnc= encjson.encryptproperty(Object.keys(testData0)[0]);
var factDec= encjson.decryptproperty(factDec);
```

Version
----

0.10

Tech
-----------

encJSON uses a number of open source projects to work properly:

* [CryptoJS] - For the Rabbit and PBKDF2 algorithms implementation.
* [QUnit] - To test this library.

License
----

GPL

**Free Software, Hell Yeah!**

[CryptoJS]:https://code.google.com/p/crypto-js/
[QUnit]:https://github.com/jquery/qunit
[@pabloae]:http://twitter.com/pabloae
[Rabbit]:http://en.wikipedia.org/wiki/Rabbit_(cipher)
[PBKDF2]:http://en.wikipedia.org/wiki/PBKDF2
[TaffyDB]:https://github.com/typicaljoe/taffydb
[tests]: https://github.com/pabloae/encjson/tree/master/test
