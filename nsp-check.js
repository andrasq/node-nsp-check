/**
 * nsp-check -- like `nsp check` that npm deleted
 *
 * 2018-12-20 - AR.
 */

'use strict';

var npmAuditsUrl = 'https://registry.npmjs.org/-/npm/v1/security/audits';
var semverNumberRegex = /^(\d+)\.(\d+)\.(\d+)$/;

var fs = require('fs');
var util = require('util');
var https = require('http');
var qgetopt = require('qgetopt');
var semver = require('semver');
var qhttp = require('qhttp').defaults({
    xagent: new https.Agent({
        keepAlive: true,
        maxSockets: 20,
        maxFreeSockets: 4,
    }),
});

var opts = qgetopt.getopt(process.argv, "p:(-package):");
var whichDeps = {
    dependencies: true,
    optionalDependencies: true,
    devDependencies: false,
    optionalDevDependencies: false,
    peerDependencies: false,
};
var jsonfile = opts.p || opts.package || './package';


var deps = getDepsOfJson(require(jsonfile), whichDeps, function(err, ret) {
    console.log("AR: Done. deps=", util.inspect(ret, { depth: 6 }));
})


/**
 * given a package json pjson, return its dependencies
 * The returned object has properties { name, version, requires, dependencies }
 * where requires is the name:version mapping from the json file, and
 * dependencies is a recursive name:getDepsOfJson() mapping of the sub-dependencies.
 */
function getDepsOfJson( pjson, whichDeps, callback ) {
console.log("AR: getDepsOfJson of", pjson.name);
    var name = pjson.name || 'main';
    var version = pjson.version || '0.0.1';

    var deps = {
        name: name,
        version: version,
        requires: {},
        dependencies: {}
    };

    deps.dependencies = objectAssign(
        deps.dependencies,
        whichDeps.devDependencies ? pjson.devDependencies : {},
        whichDeps.optionalDevDependencies ? pjson.optionalDevDependencies : {},
        whichDeps.optionalDependencies ? pjson.optionalDependencies : {},
        // not peerDependencies
        whichDeps.dependencies ? pjson.dependencies : {}
    );

    for (var k in deps.dependencies) {
        deps.requires[k] = deps.dependencies[k];
    }
console.log("AR: ---- pjson reqs", name, deps.requires);

    // for each dependency, replace dependencies with the sub-deps object
    forEach(
        Object.keys(deps.requires),
        function(name, cb) {
            var version = deps.requires[name];
console.log("AR: subdep", name, version);

            getPJson(name, version, function(err, json) {
                if (err) return cb(err);
                if (!json) return cb(new Error('did not get a pjson object'));

console.log("AR: getting subdeps of dep %s@%s", json.name, json.version);
                getDepsOfJson(json, whichDeps, function(err, subDeps) {
console.log("AR: BACK");
console.log("AR: got subdeps pjson for", err, json.name, subDeps.name, subDeps.version, subDeps.requires);
                    // assert subDeps.version == deps.requires[name]
                    deps.dependencies[name] = subDeps;
                    cb();
                })
            })
        },
        function(err) {
console.log("AR: all done getting subdeps of", pjson.name);
            callback(err, deps);
        }
    );
}

/**
 * get the package.json of the named module from npmjs.org
 */
function getPJson( name, version, userCallback ) {
    // TODO: cache already seen info
    // TODO: persistent-cache already seen info, eg in ~/.npm/<package>/<version>
console.log("AR: mark: getPJson", name, version);

    function callback(err, ret) {
console.log("AR: getPJson returning", name);
        userCallback(err, ret);
    }

    if (semverNumberRegex.test(version)) {
console.log("AR: version is semver");
        var pjson = getCachedPJson(name, version);
        // TODO: option to bypass the cache, re-fetch everything
        if (pjson) { setImmediate(callback, null, pjson); return }

        qhttp.get('https://registry.npmjs.org/' + urlencode(name) + '/' + urlencode(version), function(err, res, body) {
            // nb: "GET is not allowed" MethodNotAllowedError means "not found" (eg '*' or '1.0')
            if (err) return callback(err);
            body = tryJsonDecode(String(body));
            if (body instanceof Error) return callback(new Error('unable to decode response: ' + body));
            callback(null, body);
        })
    }
    else if (/[a-zA-Z#:/]/.test(version)) {
console.log("AR: version is text");
        // FIXME: version could be a url or git tag, handle those too
        throw new Error(version + ': url path versions not handled yet');
    }
    else {
console.log("AR: version is other", version);

// TODO: only retrieve the versions, not everything
// TODO: ? warn about under-constrained dependency
// FIXME: handle '*' and '>= 1.2' etc
        qhttp.get('https://registry.npmjs.org/' + urlencode(name), function(err, res, body) {
            if (err) return callback(err);
            body = tryJsonDecode(String(body));
            if (body instanceof Error) return callback(new Error('unable to decode response: ' + body));
            var bestVersion = selectBestVersion(Object.keys(body.versions), version);
console.log("AR: other version using",  bestVersion);
            getPJson(name, bestVersion, callback);
        })
    }
}

function getCachedPJson( name, version ) {
    if (!process.env.HOME) return null;
    var path = process.env.HOME + '/.npm/' + name + '/' + version + '/package/package.json';

    var body;
    try { body = fs.readFileSync(path) }
    catch (err) { return null }

    var json = tryJsonDecode(body);
    if (json instanceof Error) return null;

    return json;
}

function selectBestVersion( versions, wantVersion ) {
    // try versions in descending order, to minimize calls to semver.satisfies
    versions.sort(function(a, b) { return isSemverLt(a, b) ? 1 : -1 });
    for (var i=0; i<versions.length; i++) {
        // highest matching version wins
        if (isSemverMatch(versions[i], wantVersion)) return versions[i];
    }
    return '';
}

function isSemverMatch( tryVer, wantVer ) {
    // nb: semver is rather slow, .gt is 400k/s and .satisfies is 100k/s
    try { return semver.satisfies(tryVer, wantVer) }
    catch (err) { return false }
}

// return true if semver ver1 is < ver2
// Both version numbers must be a numeric dotted triples, eg "1.3.7"
// semver.lt() is 500k/s, this function is 7000k/s
function isSemverLt( ver1, ver2 ) {
    var parts1 = String(ver1).match(semverNumberRegex);
    var parts2 = String(ver2).match(semverNumberRegex);
    if (!parts1 || !parts2) return semver.lt(ver1, ver2);

    if (+parts1[1] < +parts2[1]) return true;

    if (parts1[1] !== parts2[1]) return false;
    if (+parts1[2] < +parts2[2]) return true;

    if (parts1[2] !== parts2[2]) return false;
    if (+parts1[3] < +parts2[3]) return true;

    return false;
}

function forEach( items, func, callback ) {
    var nexpect = items.length, ndone = 0;
    var returnError = null;

    if (!items.length) return callback();
    for (var i=0; i<nexpect; i++) processItem(items[i]);

    function processItem( item ) {
        func(item, function(err) {
            ndone += 1;
console.log("AR: forEach %d done of %d", ndone, nexpect);
            if (err && !returnError) returnError = err;
            if (ndone === nexpect) {
                callback(returnError);
            }
        })
    }
}

function urlencode( str ) {
    return encodeURIComponent(str);
}

function tryJsonDecode( str ) {
    try { return JSON.parse(str) } catch (err) { return err }
}

function objectAssign( target ) {
    for (var i=1; i<arguments.length; i++) {
        for (var k in arguments[i]) target[k] = arguments[i][k];
    }
    return target;
}


/* quicktest:

var qtimeit = require('qtimeit');
var x;
qtimeit(1000000, function() { x = isSemverLt("1.0.2", "1.0.1") });
console.log("AR: .lt", x);

/**/
