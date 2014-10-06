/*
	The CryptoJS and CryptoJS are modifications of the ones in CryptoJS v3.1.2
	code.google.com/p/crypto-js
	(c) 2014 by Pablo Alonso Esparza. All rights reserved.
	code.google.com/p/crypto-js/wiki/License
	*/
var encjson=(function () {
	var module = {};
	/*
	The rabbit and pbkdf2 algorithm implementations are modifications of the ones in CryptoJS v3.1.2
	code.google.com/p/crypto-js/wiki/License
	*/
	//Rabbit
	var CryptoJS=CryptoJS||function(e,t){var n={},r=n.lib={},i=function(){},s=r.Base={extend:function(e){i.prototype=this;var t=new i;e&&t.mixIn(e);t.hasOwnProperty("init")||(t.init=function(){t.$super.init.apply(this,arguments)});t.init.prototype=t;t.$super=this;return t},create:function(){var e=this.extend();e.init.apply(e,arguments);return e},init:function(){},mixIn:function(e){for(var t in e)e.hasOwnProperty(t)&&(this[t]=e[t]);e.hasOwnProperty("toString")&&(this.toString=e.toString)},clone:function(){return this.init.prototype.extend(this)}},o=r.WordArray=s.extend({init:function(e,n){e=this.words=e||[];this.sigBytes=n!=t?n:4*e.length},toString:function(e){return(e||a).stringify(this)},concat:function(e){var t=this.words,n=e.words,r=this.sigBytes;e=e.sigBytes;this.clamp();if(r%4)for(var i=0;i<e;i++)t[r+i>>>2]|=(n[i>>>2]>>>24-8*(i%4)&255)<<24-8*((r+i)%4);else if(65535<n.length)for(i=0;i<e;i+=4)t[r+i>>>2]=n[i>>>2];else t.push.apply(t,n);this.sigBytes+=e;return this},clamp:function(){var t=this.words,n=this.sigBytes;t[n>>>2]&=4294967295<<32-8*(n%4);t.length=e.ceil(n/4)},clone:function(){var e=s.clone.call(this);e.words=this.words.slice(0);return e},random:function(t){for(var n=[],r=0;r<t;r+=4)n.push(4294967296*e.random()|0);return new o.init(n,t)}}),u=n.enc={},a=u.Hex={stringify:function(e){var t=e.words;e=e.sigBytes;for(var n=[],r=0;r<e;r++){var i=t[r>>>2]>>>24-8*(r%4)&255;n.push((i>>>4).toString(16));n.push((i&15).toString(16))}return n.join("")},parse:function(e){for(var t=e.length,n=[],r=0;r<t;r+=2)n[r>>>3]|=parseInt(e.substr(r,2),16)<<24-4*(r%8);return new o.init(n,t/2)}},f=u.Latin1={stringify:function(e){var t=e.words;e=e.sigBytes;for(var n=[],r=0;r<e;r++)n.push(String.fromCharCode(t[r>>>2]>>>24-8*(r%4)&255));return n.join("")},parse:function(e){for(var t=e.length,n=[],r=0;r<t;r++)n[r>>>2]|=(e.charCodeAt(r)&255)<<24-8*(r%4);return new o.init(n,t)}},l=u.Utf8={stringify:function(e){try{return decodeURIComponent(escape(f.stringify(e)))}catch(t){throw Error("Malformed UTF-8 data")}},parse:function(e){return f.parse(unescape(encodeURIComponent(e)))}},c=r.BufferedBlockAlgorithm=s.extend({reset:function(){this._data=new o.init;this._nDataBytes=0},_append:function(e){"string"==typeof e&&(e=l.parse(e));this._data.concat(e);this._nDataBytes+=e.sigBytes},_process:function(t){var n=this._data,r=n.words,i=n.sigBytes,s=this.blockSize,u=i/(4*s),u=t?e.ceil(u):e.max((u|0)-this._minBufferSize,0);t=u*s;i=e.min(4*t,i);if(t){for(var a=0;a<t;a+=s)this._doProcessBlock(r,a);a=r.splice(0,t);n.sigBytes-=i}return new o.init(a,i)},clone:function(){var e=s.clone.call(this);e._data=this._data.clone();return e},_minBufferSize:0});r.Hasher=c.extend({cfg:s.extend(),init:function(e){this.cfg=this.cfg.extend(e);this.reset()},reset:function(){c.reset.call(this);this._doReset()},update:function(e){this._append(e);this._process();return this},finalize:function(e){e&&this._append(e);return this._doFinalize()},blockSize:16,_createHelper:function(e){return function(t,n){return(new e.init(n)).finalize(t)}},_createHmacHelper:function(e){return function(t,n){return(new h.HMAC.init(e,n)).finalize(t)}}});var h=n.algo={};return n}(Math);(function(){var e=CryptoJS,t=e.lib.WordArray;e.enc.Base64={stringify:function(e){var t=e.words,n=e.sigBytes,r=this._map;e.clamp();e=[];for(var i=0;i<n;i+=3)for(var s=(t[i>>>2]>>>24-8*(i%4)&255)<<16|(t[i+1>>>2]>>>24-8*((i+1)%4)&255)<<8|t[i+2>>>2]>>>24-8*((i+2)%4)&255,o=0;4>o&&i+.75*o<n;o++)e.push(r.charAt(s>>>6*(3-o)&63));if(t=r.charAt(64))for(;e.length%4;)e.push(t);return e.join("")},parse:function(e){var n=e.length,r=this._map,i=r.charAt(64);i&&(i=e.indexOf(i),-1!=i&&(n=i));for(var i=[],s=0,o=0;o<n;o++)if(o%4){var u=r.indexOf(e.charAt(o-1))<<2*(o%4),a=r.indexOf(e.charAt(o))>>>6-2*(o%4);i[s>>>2]|=(u|a)<<24-8*(s%4);s++}return t.create(i,s)},_map:"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="}})();(function(e){function t(e,t,n,r,i,s,o){e=e+(t&n|~t&r)+i+o;return(e<<s|e>>>32-s)+t}function n(e,t,n,r,i,s,o){e=e+(t&r|n&~r)+i+o;return(e<<s|e>>>32-s)+t}function r(e,t,n,r,i,s,o){e=e+(t^n^r)+i+o;return(e<<s|e>>>32-s)+t}function i(e,t,n,r,i,s,o){e=e+(n^(t|~r))+i+o;return(e<<s|e>>>32-s)+t}for(var s=CryptoJS,o=s.lib,u=o.WordArray,a=o.Hasher,o=s.algo,f=[],l=0;64>l;l++)f[l]=4294967296*e.abs(e.sin(l+1))|0;o=o.MD5=a.extend({_doReset:function(){this._hash=new u.init([1732584193,4023233417,2562383102,271733878])},_doProcessBlock:function(e,s){for(var o=0;16>o;o++){var u=s+o,a=e[u];e[u]=(a<<8|a>>>24)&16711935|(a<<24|a>>>8)&4278255360}var o=this._hash.words,u=e[s+0],a=e[s+1],l=e[s+2],c=e[s+3],h=e[s+4],d=e[s+5],v=e[s+6],m=e[s+7],g=e[s+8],y=e[s+9],b=e[s+10],w=e[s+11],E=e[s+12],S=e[s+13],x=e[s+14],T=e[s+15],N=o[0],C=o[1],L=o[2],A=o[3],N=t(N,C,L,A,u,7,f[0]),A=t(A,N,C,L,a,12,f[1]),L=t(L,A,N,C,l,17,f[2]),C=t(C,L,A,N,c,22,f[3]),N=t(N,C,L,A,h,7,f[4]),A=t(A,N,C,L,d,12,f[5]),L=t(L,A,N,C,v,17,f[6]),C=t(C,L,A,N,m,22,f[7]),N=t(N,C,L,A,g,7,f[8]),A=t(A,N,C,L,y,12,f[9]),L=t(L,A,N,C,b,17,f[10]),C=t(C,L,A,N,w,22,f[11]),N=t(N,C,L,A,E,7,f[12]),A=t(A,N,C,L,S,12,f[13]),L=t(L,A,N,C,x,17,f[14]),C=t(C,L,A,N,T,22,f[15]),N=n(N,C,L,A,a,5,f[16]),A=n(A,N,C,L,v,9,f[17]),L=n(L,A,N,C,w,14,f[18]),C=n(C,L,A,N,u,20,f[19]),N=n(N,C,L,A,d,5,f[20]),A=n(A,N,C,L,b,9,f[21]),L=n(L,A,N,C,T,14,f[22]),C=n(C,L,A,N,h,20,f[23]),N=n(N,C,L,A,y,5,f[24]),A=n(A,N,C,L,x,9,f[25]),L=n(L,A,N,C,c,14,f[26]),C=n(C,L,A,N,g,20,f[27]),N=n(N,C,L,A,S,5,f[28]),A=n(A,N,C,L,l,9,f[29]),L=n(L,A,N,C,m,14,f[30]),C=n(C,L,A,N,E,20,f[31]),N=r(N,C,L,A,d,4,f[32]),A=r(A,N,C,L,g,11,f[33]),L=r(L,A,N,C,w,16,f[34]),C=r(C,L,A,N,x,23,f[35]),N=r(N,C,L,A,a,4,f[36]),A=r(A,N,C,L,h,11,f[37]),L=r(L,A,N,C,m,16,f[38]),C=r(C,L,A,N,b,23,f[39]),N=r(N,C,L,A,S,4,f[40]),A=r(A,N,C,L,u,11,f[41]),L=r(L,A,N,C,c,16,f[42]),C=r(C,L,A,N,v,23,f[43]),N=r(N,C,L,A,y,4,f[44]),A=r(A,N,C,L,E,11,f[45]),L=r(L,A,N,C,T,16,f[46]),C=r(C,L,A,N,l,23,f[47]),N=i(N,C,L,A,u,6,f[48]),A=i(A,N,C,L,m,10,f[49]),L=i(L,A,N,C,x,15,f[50]),C=i(C,L,A,N,d,21,f[51]),N=i(N,C,L,A,E,6,f[52]),A=i(A,N,C,L,c,10,f[53]),L=i(L,A,N,C,b,15,f[54]),C=i(C,L,A,N,a,21,f[55]),N=i(N,C,L,A,g,6,f[56]),A=i(A,N,C,L,T,10,f[57]),L=i(L,A,N,C,v,15,f[58]),C=i(C,L,A,N,S,21,f[59]),N=i(N,C,L,A,h,6,f[60]),A=i(A,N,C,L,w,10,f[61]),L=i(L,A,N,C,l,15,f[62]),C=i(C,L,A,N,y,21,f[63]);o[0]=o[0]+N|0;o[1]=o[1]+C|0;o[2]=o[2]+L|0;o[3]=o[3]+A|0},_doFinalize:function(){var t=this._data,n=t.words,r=8*this._nDataBytes,i=8*t.sigBytes;n[i>>>5]|=128<<24-i%32;var s=e.floor(r/4294967296);n[(i+64>>>9<<4)+15]=(s<<8|s>>>24)&16711935|(s<<24|s>>>8)&4278255360;n[(i+64>>>9<<4)+14]=(r<<8|r>>>24)&16711935|(r<<24|r>>>8)&4278255360;t.sigBytes=4*(n.length+1);this._process();t=this._hash;n=t.words;for(r=0;4>r;r++)i=n[r],n[r]=(i<<8|i>>>24)&16711935|(i<<24|i>>>8)&4278255360;return t},clone:function(){var e=a.clone.call(this);e._hash=this._hash.clone();return e}});s.MD5=a._createHelper(o);s.HmacMD5=a._createHmacHelper(o)})(Math);(function(){var e=CryptoJS,t=e.lib,n=t.Base,r=t.WordArray,t=e.algo,i=t.EvpKDF=n.extend({cfg:n.extend({keySize:4,hasher:t.MD5,iterations:1}),init:function(e){this.cfg=this.cfg.extend(e)},compute:function(e,t){for(var n=this.cfg,i=n.hasher.create(),s=r.create(),o=s.words,u=n.keySize,n=n.iterations;o.length<u;){a&&i.update(a);var a=i.update(e).finalize(t);i.reset();for(var f=1;f<n;f++)a=i.finalize(a),i.reset();s.concat(a)}s.sigBytes=4*u;return s}});e.EvpKDF=function(e,t,n){return i.create(n).compute(e,t)}})();CryptoJS.lib.Cipher||function(e){var t=CryptoJS,n=t.lib,r=n.Base,i=n.WordArray,s=n.BufferedBlockAlgorithm,o=t.enc.Base64,u=t.algo.EvpKDF,a=n.Cipher=s.extend({cfg:r.extend(),createEncryptor:function(e,t){return this.create(this._ENC_XFORM_MODE,e,t)},createDecryptor:function(e,t){return this.create(this._DEC_XFORM_MODE,e,t)},init:function(e,t,n){this.cfg=this.cfg.extend(n);this._xformMode=e;this._key=t;this.reset()},reset:function(){s.reset.call(this);this._doReset()},process:function(e){this._append(e);return this._process()},finalize:function(e){e&&this._append(e);return this._doFinalize()},keySize:4,ivSize:4,_ENC_XFORM_MODE:1,_DEC_XFORM_MODE:2,_createHelper:function(e){return{encrypt:function(t,n,r){return("string"==typeof n?d:p).encrypt(e,t,n,r)},decrypt:function(t,n,r){return("string"==typeof n?d:p).decrypt(e,t,n,r)}}}});n.StreamCipher=a.extend({_doFinalize:function(){return this._process(!0)},blockSize:1});var f=t.mode={},l=function(t,n,r){var i=this._iv;i?this._iv=e:i=this._prevBlock;for(var s=0;s<r;s++)t[n+s]^=i[s]},c=(n.BlockCipherMode=r.extend({createEncryptor:function(e,t){return this.Encryptor.create(e,t)},createDecryptor:function(e,t){return this.Decryptor.create(e,t)},init:function(e,t){this._cipher=e;this._iv=t}})).extend();c.Encryptor=c.extend({processBlock:function(e,t){var n=this._cipher,r=n.blockSize;l.call(this,e,t,r);n.encryptBlock(e,t);this._prevBlock=e.slice(t,t+r)}});c.Decryptor=c.extend({processBlock:function(e,t){var n=this._cipher,r=n.blockSize,i=e.slice(t,t+r);n.decryptBlock(e,t);l.call(this,e,t,r);this._prevBlock=i}});f=f.CBC=c;c=(t.pad={}).Pkcs7={pad:function(e,t){for(var n=4*t,n=n-e.sigBytes%n,r=n<<24|n<<16|n<<8|n,s=[],o=0;o<n;o+=4)s.push(r);n=i.create(s,n);e.concat(n)},unpad:function(e){e.sigBytes-=e.words[e.sigBytes-1>>>2]&255}};n.BlockCipher=a.extend({cfg:a.cfg.extend({mode:f,padding:c}),reset:function(){a.reset.call(this);var e=this.cfg,t=e.iv,e=e.mode;if(this._xformMode==this._ENC_XFORM_MODE)var n=e.createEncryptor;else n=e.createDecryptor,this._minBufferSize=1;this._mode=n.call(e,this,t&&t.words)},_doProcessBlock:function(e,t){this._mode.processBlock(e,t)},_doFinalize:function(){var e=this.cfg.padding;if(this._xformMode==this._ENC_XFORM_MODE){e.pad(this._data,this.blockSize);var t=this._process(!0)}else t=this._process(!0),e.unpad(t);return t},blockSize:4});var h=n.CipherParams=r.extend({init:function(e){this.mixIn(e)},toString:function(e){return(e||this.formatter).stringify(this)}}),f=(t.format={}).OpenSSL={stringify:function(e){var t=e.ciphertext;e=e.salt;return(e?i.create([1398893684,1701076831]).concat(e).concat(t):t).toString(o)},parse:function(e){e=o.parse(e);var t=e.words;if(1398893684==t[0]&&1701076831==t[1]){var n=i.create(t.slice(2,4));t.splice(0,4);e.sigBytes-=16}return h.create({ciphertext:e,salt:n})}},p=n.SerializableCipher=r.extend({cfg:r.extend({format:f}),encrypt:function(e,t,n,r){r=this.cfg.extend(r);var i=e.createEncryptor(n,r);t=i.finalize(t);i=i.cfg;return h.create({ciphertext:t,key:n,iv:i.iv,algorithm:e,mode:i.mode,padding:i.padding,blockSize:e.blockSize,formatter:r.format})},decrypt:function(e,t,n,r){r=this.cfg.extend(r);t=this._parse(t,r.format);return e.createDecryptor(n,r).finalize(t.ciphertext)},_parse:function(e,t){return"string"==typeof e?t.parse(e,this):e}}),t=(t.kdf={}).OpenSSL={execute:function(e,t,n,r){r||(r=i.random(8));e=u.create({keySize:t+n}).compute(e,r);n=i.create(e.words.slice(t),4*n);e.sigBytes=4*t;return h.create({key:e,iv:n,salt:r})}},d=n.PasswordBasedCipher=p.extend({cfg:p.cfg.extend({kdf:t}),encrypt:function(e,t,n,r){r=this.cfg.extend(r);n=r.kdf.execute(n,e.keySize,e.ivSize);r.iv=n.iv;e=p.encrypt.call(this,e,t,n.key,r);e.mixIn(n);return e},decrypt:function(e,t,n,r){r=this.cfg.extend(r);t=this._parse(t,r.format);n=r.kdf.execute(n,e.keySize,e.ivSize,t.salt);r.iv=n.iv;return p.decrypt.call(this,e,t,n.key,r)}})}();(function(){function e(){for(var e=this._X,t=this._C,n=0;8>n;n++)i[n]=t[n];t[0]=t[0]+1295307597+this._b|0;t[1]=t[1]+3545052371+(t[0]>>>0<i[0]>>>0?1:0)|0;t[2]=t[2]+886263092+(t[1]>>>0<i[1]>>>0?1:0)|0;t[3]=t[3]+1295307597+(t[2]>>>0<i[2]>>>0?1:0)|0;t[4]=t[4]+3545052371+(t[3]>>>0<i[3]>>>0?1:0)|0;t[5]=t[5]+886263092+(t[4]>>>0<i[4]>>>0?1:0)|0;t[6]=t[6]+1295307597+(t[5]>>>0<i[5]>>>0?1:0)|0;t[7]=t[7]+3545052371+(t[6]>>>0<i[6]>>>0?1:0)|0;this._b=t[7]>>>0<i[7]>>>0?1:0;for(n=0;8>n;n++){var r=e[n]+t[n],o=r&65535,u=r>>>16;s[n]=((o*o>>>17)+o*u>>>15)+u*u^((r&4294901760)*r|0)+((r&65535)*r|0)}e[0]=s[0]+(s[7]<<16|s[7]>>>16)+(s[6]<<16|s[6]>>>16)|0;e[1]=s[1]+(s[0]<<8|s[0]>>>24)+s[7]|0;e[2]=s[2]+(s[1]<<16|s[1]>>>16)+(s[0]<<16|s[0]>>>16)|0;e[3]=s[3]+(s[2]<<8|s[2]>>>24)+s[1]|0;e[4]=s[4]+(s[3]<<16|s[3]>>>16)+(s[2]<<16|s[2]>>>16)|0;e[5]=s[5]+(s[4]<<8|s[4]>>>24)+s[3]|0;e[6]=s[6]+(s[5]<<16|s[5]>>>16)+(s[4]<<16|s[4]>>>16)|0;e[7]=s[7]+(s[6]<<8|s[6]>>>24)+s[5]|0}var t=CryptoJS,n=t.lib.StreamCipher,r=[],i=[],s=[],o=t.algo.Rabbit=n.extend({_doReset:function(){for(var t=this._key.words,n=this.cfg.iv,r=0;4>r;r++)t[r]=(t[r]<<8|t[r]>>>24)&16711935|(t[r]<<24|t[r]>>>8)&4278255360;for(var i=this._X=[t[0],t[3]<<16|t[2]>>>16,t[1],t[0]<<16|t[3]>>>16,t[2],t[1]<<16|t[0]>>>16,t[3],t[2]<<16|t[1]>>>16],t=this._C=[t[2]<<16|t[2]>>>16,t[0]&4294901760|t[1]&65535,t[3]<<16|t[3]>>>16,t[1]&4294901760|t[2]&65535,t[0]<<16|t[0]>>>16,t[2]&4294901760|t[3]&65535,t[1]<<16|t[1]>>>16,t[3]&4294901760|t[0]&65535],r=this._b=0;4>r;r++)e.call(this);for(r=0;8>r;r++)t[r]^=i[r+4&7];if(n){var r=n.words,n=r[0],r=r[1],n=(n<<8|n>>>24)&16711935|(n<<24|n>>>8)&4278255360,r=(r<<8|r>>>24)&16711935|(r<<24|r>>>8)&4278255360,i=n>>>16|r&4294901760,s=r<<16|n&65535;t[0]^=n;t[1]^=i;t[2]^=r;t[3]^=s;t[4]^=n;t[5]^=i;t[6]^=r;t[7]^=s;for(r=0;4>r;r++)e.call(this)}},_doProcessBlock:function(t,n){var i=this._X;e.call(this);r[0]=i[0]^i[5]>>>16^i[3]<<16;r[1]=i[2]^i[7]>>>16^i[5]<<16;r[2]=i[4]^i[1]>>>16^i[7]<<16;r[3]=i[6]^i[3]>>>16^i[1]<<16;for(i=0;4>i;i++)r[i]=(r[i]<<8|r[i]>>>24)&16711935|(r[i]<<24|r[i]>>>8)&4278255360,t[n+i]^=r[i]},blockSize:4,ivSize:2});t.Rabbit=n._createHelper(o)})();
	//pbkdf2
	CryptoJS=CryptoJS||function(e,t){var n={},r=n.lib={},i=function(){},s=r.Base={extend:function(e){i.prototype=this;var t=new i;e&&t.mixIn(e);t.hasOwnProperty("init")||(t.init=function(){t.$super.init.apply(this,arguments)});t.init.prototype=t;t.$super=this;return t},create:function(){var e=this.extend();e.init.apply(e,arguments);return e},init:function(){},mixIn:function(e){for(var t in e)e.hasOwnProperty(t)&&(this[t]=e[t]);e.hasOwnProperty("toString")&&(this.toString=e.toString)},clone:function(){return this.init.prototype.extend(this)}},o=r.WordArray=s.extend({init:function(e,n){e=this.words=e||[];this.sigBytes=n!=t?n:4*e.length},toString:function(e){return(e||a).stringify(this)},concat:function(e){var t=this.words,n=e.words,r=this.sigBytes;e=e.sigBytes;this.clamp();if(r%4)for(var i=0;i<e;i++)t[r+i>>>2]|=(n[i>>>2]>>>24-8*(i%4)&255)<<24-8*((r+i)%4);else if(65535<n.length)for(i=0;i<e;i+=4)t[r+i>>>2]=n[i>>>2];else t.push.apply(t,n);this.sigBytes+=e;return this},clamp:function(){var t=this.words,n=this.sigBytes;t[n>>>2]&=4294967295<<32-8*(n%4);t.length=e.ceil(n/4)},clone:function(){var e=s.clone.call(this);e.words=this.words.slice(0);return e},random:function(t){for(var n=[],r=0;r<t;r+=4)n.push(4294967296*e.random()|0);return new o.init(n,t)}}),u=n.enc={},a=u.Hex={stringify:function(e){var t=e.words;e=e.sigBytes;for(var n=[],r=0;r<e;r++){var i=t[r>>>2]>>>24-8*(r%4)&255;n.push((i>>>4).toString(16));n.push((i&15).toString(16))}return n.join("")},parse:function(e){for(var t=e.length,n=[],r=0;r<t;r+=2)n[r>>>3]|=parseInt(e.substr(r,2),16)<<24-4*(r%8);return new o.init(n,t/2)}},f=u.Latin1={stringify:function(e){var t=e.words;e=e.sigBytes;for(var n=[],r=0;r<e;r++)n.push(String.fromCharCode(t[r>>>2]>>>24-8*(r%4)&255));return n.join("")},parse:function(e){for(var t=e.length,n=[],r=0;r<t;r++)n[r>>>2]|=(e.charCodeAt(r)&255)<<24-8*(r%4);return new o.init(n,t)}},l=u.Utf8={stringify:function(e){try{return decodeURIComponent(escape(f.stringify(e)))}catch(t){throw Error("Malformed UTF-8 data")}},parse:function(e){return f.parse(unescape(encodeURIComponent(e)))}},c=r.BufferedBlockAlgorithm=s.extend({reset:function(){this._data=new o.init;this._nDataBytes=0},_append:function(e){"string"==typeof e&&(e=l.parse(e));this._data.concat(e);this._nDataBytes+=e.sigBytes},_process:function(t){var n=this._data,r=n.words,i=n.sigBytes,s=this.blockSize,u=i/(4*s),u=t?e.ceil(u):e.max((u|0)-this._minBufferSize,0);t=u*s;i=e.min(4*t,i);if(t){for(var a=0;a<t;a+=s)this._doProcessBlock(r,a);a=r.splice(0,t);n.sigBytes-=i}return new o.init(a,i)},clone:function(){var e=s.clone.call(this);e._data=this._data.clone();return e},_minBufferSize:0});r.Hasher=c.extend({cfg:s.extend(),init:function(e){this.cfg=this.cfg.extend(e);this.reset()},reset:function(){c.reset.call(this);this._doReset()},update:function(e){this._append(e);this._process();return this},finalize:function(e){e&&this._append(e);return this._doFinalize()},blockSize:16,_createHelper:function(e){return function(t,n){return(new e.init(n)).finalize(t)}},_createHmacHelper:function(e){return function(t,n){return(new h.HMAC.init(e,n)).finalize(t)}}});var h=n.algo={};return n}(Math);(function(){var e=CryptoJS,t=e.lib,n=t.WordArray,r=t.Hasher,i=[],t=e.algo.SHA1=r.extend({_doReset:function(){this._hash=new n.init([1732584193,4023233417,2562383102,271733878,3285377520])},_doProcessBlock:function(e,t){for(var n=this._hash.words,r=n[0],s=n[1],o=n[2],u=n[3],a=n[4],f=0;80>f;f++){if(16>f)i[f]=e[t+f]|0;else{var l=i[f-3]^i[f-8]^i[f-14]^i[f-16];i[f]=l<<1|l>>>31}l=(r<<5|r>>>27)+a+i[f];l=20>f?l+((s&o|~s&u)+1518500249):40>f?l+((s^o^u)+1859775393):60>f?l+((s&o|s&u|o&u)-1894007588):l+((s^o^u)-899497514);a=u;u=o;o=s<<30|s>>>2;s=r;r=l}n[0]=n[0]+r|0;n[1]=n[1]+s|0;n[2]=n[2]+o|0;n[3]=n[3]+u|0;n[4]=n[4]+a|0},_doFinalize:function(){var e=this._data,t=e.words,n=8*this._nDataBytes,r=8*e.sigBytes;t[r>>>5]|=128<<24-r%32;t[(r+64>>>9<<4)+14]=Math.floor(n/4294967296);t[(r+64>>>9<<4)+15]=n;e.sigBytes=4*t.length;this._process();return this._hash},clone:function(){var e=r.clone.call(this);e._hash=this._hash.clone();return e}});e.SHA1=r._createHelper(t);e.HmacSHA1=r._createHmacHelper(t)})();(function(){var e=CryptoJS,t=e.enc.Utf8;e.algo.HMAC=e.lib.Base.extend({init:function(e,n){e=this._hasher=new e.init;"string"==typeof n&&(n=t.parse(n));var r=e.blockSize,i=4*r;n.sigBytes>i&&(n=e.finalize(n));n.clamp();for(var s=this._oKey=n.clone(),o=this._iKey=n.clone(),u=s.words,a=o.words,f=0;f<r;f++)u[f]^=1549556828,a[f]^=909522486;s.sigBytes=o.sigBytes=i;this.reset()},reset:function(){var e=this._hasher;e.reset();e.update(this._iKey)},update:function(e){this._hasher.update(e);return this},finalize:function(e){var t=this._hasher;e=t.finalize(e);t.reset();return t.finalize(this._oKey.clone().concat(e))}})})();(function(){var e=CryptoJS,t=e.lib,n=t.Base,r=t.WordArray,t=e.algo,i=t.HMAC,s=t.PBKDF2=n.extend({cfg:n.extend({keySize:4,hasher:t.SHA1,iterations:1}),init:function(e){this.cfg=this.cfg.extend(e)},compute:function(e,t){for(var n=this.cfg,s=i.create(n.hasher,e),o=r.create(),u=r.create([1]),a=o.words,f=u.words,l=n.keySize,n=n.iterations;a.length<l;){var c=s.update(t).finalize(u);s.reset();for(var h=c.words,p=h.length,v=c,g=1;g<n;g++){v=s.finalize(v);s.reset();for(var y=v.words,b=0;b<p;b++)h[b]^=y[b]}o.concat(c);f[0]++}o.sigBytes=4*l;return o}});e.PBKDF2=function(e,t,n){return s.create(n).compute(e,t)}})();
	//password variables
	var password, passwordProp;
	
	// ****************************************
    // *
    // * Sets password using PBKDF2 password-based key derivation function.
	// * The password will be of 512 Bits 
	// * Arguments: passphrase, nº of iterations of the algorithm (default: 1000 iterations)
    // * Purpose: Sets a password for the json encryption
    // *
    // ****************************************  
	module.setpassword= function(pwd, iterations){
		if (iterations === undefined) {
			iterations= 1000;
		}
		password = CryptoJS.PBKDF2(pwd, CryptoJS.lib.WordArray.random(128/8), { keySize: 512/32, iterations: iterations }).toString();
		passwordProp = CryptoJS.PBKDF2(pwd, CryptoJS.lib.WordArray.random(128/8), { keySize: 512/32, iterations: iterations }).toString();
	};
	// ****************************************
    // *
    // * Sets random password using PBKDF2 password-based key derivation function (with 1000 Iterations).
	// * The passphrase to use with this algorithm is a random alphanumeric string with a length from 8 to 15
	// * The password will be of 512 Bits 
    // * Purpose: Sets a random password for the json encryption
    // *
    // ****************************************  
	module.setrandompassword=function(){
		var N = Math.floor(Math.random() * 8) + 8;
		var pwd = new Array(N+1).join((Math.random().toString(36)+'00000000000000000').slice(2, 18)).slice(0, N);
		module.setpassword(pwd);
	}
	// ****************************************
    // *
    // * Sets password without using any password-based key derivation function.
	// * 
    // * Purpose: Sets a password for the json encryption
    // *
    // ****************************************  
	module.setrawpassword= function(pwd){
		password=pwd;
		passwordProp=pwd;
	};
	function parseString(value){
		if (isNaN(value) ){
			if(value ==='true' || value ==='false'){
				return (value === 'true');
			}
			else if (value !== 'null'){
				return value;
			}			else{				return null;			}
		}
		else if(value.toString().indexOf('.') != -1){
			return parseFloat(value);
		}
		else{
			return parseInt(value);
		}
	}
	function recursiveEncryptJSON(obj) {
		var destObj = {};
		for (prop in obj) {
			if(obj.hasOwnProperty(prop)) {
				var strName = 'K'+CryptoJS.Rabbit.encrypt(prop, passwordProp).toString();				
				if(Object.prototype.toString.call( obj[prop] ) === '[object Array]'){					
					destObj[strName]=[];					var aux =obj[prop];
					for (var i=0; i < aux.length; i++) {
						if (aux[i] instanceof Object) {							destObj[strName][i]= recursiveEncryptJSON(aux[i]);
						}
						else{
							destObj[strName][i] = CryptoJS.Rabbit.encrypt(''+aux[i], password).toString();
						}
					}
				}
				else if (obj[prop] instanceof Object) {
					destObj[strName]= recursiveEncryptJSON(obj[prop]);
				} else {
					destObj[strName]={};
					destObj[strName] = CryptoJS.Rabbit.encrypt(''+obj[prop], password).toString();
				}
			}
		}
		return destObj;
	}
	function recursiveDecryptJSON(obj) {
		var destObj = {};
		for (prop in obj) {
			if(obj.hasOwnProperty(prop)) {
				var strName = CryptoJS.Rabbit.decrypt(prop.substring(1), passwordProp).toString(CryptoJS.enc.Utf8);
				if(Object.prototype.toString.call( obj[prop] ) === '[object Array]'){
					destObj[strName]=[];					var aux =obj[prop];
					for (var i=0; i < aux.length; i++) {
						if (aux[i] instanceof Object) {							destObj[strName][i]= recursiveDecryptJSON(aux[i]);
						}
						else{
							destObj[strName][i] = parseString(CryptoJS.Rabbit.decrypt(aux[i], password).toString(CryptoJS.enc.Utf8));
						}
					}
				}
				else if (obj[prop] instanceof Object) {
					destObj[strName]= recursiveDecryptJSON(obj[prop]);
				} else {
					destObj[strName]={};
					destObj[strName] = parseString(CryptoJS.Rabbit.decrypt(obj[prop], password).toString(CryptoJS.enc.Utf8));
				}
			}
		}
		return destObj;
	}
	// ****************************************
    // *
    // * Encrypts a JSON. A password needs to be set before calling this function.
	// * 
    // * Purpose: Encrypt a JSON
    // *
	// * Return: Encrypted JSON
    // ****************************************  
	module.encryptjson= function(obj){		
		if(password === undefined){
			throw new Error("A password needs to be set before calling this function")
		}		else if(Object.prototype.toString.call(obj) === '[object Array]'){			var retJSON=[];			for (var i=0; i < obj.length; i++) {				retJSON[i]=recursiveEncryptJSON(obj[i]);			}			return retJSON;					}		else{
			return recursiveEncryptJSON(obj);		}
	};
	// ****************************************
    // *
    // * Decrypts a JSON. A password needs to be set before calling this function.
	// * 
    // * Purpose: Decrypt a JSON
    // *
	// * Return: Decrypted JSON
    // ****************************************  
	module.decryptjson= function(obj){
		if(password === undefined){
			throw new Error("A password needs to be set before calling this function")
		}		else if(Object.prototype.toString.call(obj) === '[object Array]'){			var retJSON=[];			for (var i=0; i < obj.length; i++) {				retJSON[i]=recursiveDecryptJSON(obj[i]);			}			return retJSON;					}		else{
			return recursiveDecryptJSON(obj);		}
	};
	// ****************************************
    // *
    // * Encrypt a JSON property. A password needs to be set before calling this function.
	// * 
    // * Purpose: Decrypt a JSON property
    // *
	// * Return: Decrypted JSON property
    // ****************************************  
	module.encryptproperty= function(prop){
		if(password === undefined){
			throw new Error("A password needs to be set before calling this function")
		}
		return 'K'+CryptoJS.Rabbit.encrypt(prop, passwordProp).toString();
	};
	// ****************************************
    // *
    // * Decrypts a JSON property. A password needs to be set before calling this function.
	// * 
    // * Purpose: Decrypt a JSON property
    // *
	// * Return: Decrypted JSON property
    // ****************************************  
	module.decryptproperty= function(prop){
		if(password === undefined){
			throw new Error("A password needs to be set before calling this function")
		}
		return CryptoJS.Rabbit.decrypt(prop.substring(1), passwordProp).toString(CryptoJS.enc.Utf8);
	};
	// ****************************************
    // *
    // * Encrypt a JSON value. A password needs to be set before calling this function.
	// * 
    // * Purpose: Encrypt a JSON value
    // *
	// * Return: Encrypted JSON value
    // **************************************** 
	module.encryptvalue= function(val){
		if(password === undefined){
			throw new Error("A password needs to be set before calling this function")
		}
		return CryptoJS.Rabbit.encrypt(''+val, password).toString();
	};
	// ****************************************
    // *
    // * Decrypts a JSON value. A password needs to be set before calling this function.
	// * 
    // * Purpose: Decrypt a JSON value
    // *
	// * Return: Decrypted JSON value
    // ****************************************  
	module.decryptvalue= function(val){
		if(password === undefined){
			throw new Error("A password needs to be set before calling this function")
		}
		return parseString(CryptoJS.Rabbit.decrypt(val, password).toString(CryptoJS.enc.Utf8));
	};

	return module;
	
    
}());