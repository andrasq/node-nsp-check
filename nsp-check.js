/**
 * nsp-check -- like `nsp check` that npm deleted
 *
 * Copyright (C) 2018 Andras Radics
 * Licensed under the Apache License, Version 2.0
 *
 * 2018-12-20 - AR.
 */

'use strict';

var npmAuditsUrl = 'https://registry.npmjs.org/-/npm/v1/security/audits';
var semverNumberRegex = /^(\d+)\.(\d+)\.(\d+)$/;

var fs = require('fs');
var util = require('util');
var Url = require('url');
var https = require('http');

var qgetopt = require('qgetopt');
var qprintf = require('qprintf');
var semver = require('semver');
var qhttp = require('qhttp').defaults({
    xagent: new https.Agent({
        keepAlive: true,
        maxSockets: 20,
        maxFreeSockets: 4,
    }),
});

// TODO: move options handling into bin/nsp-check
var opts = qgetopt.getopt(process.argv, "V(-version)h(-help)p:(-package):");

if (opts.V || opts.version) return console.log(require(__dirname + '/package.json').version);
if (opts.h || opts.help) return console.log("nsp-check [-p package]");

var whichDeps = {
    dependencies: true,
    optionalDependencies: true,
    bundledDependencies: true,
    devDependencies: false,
    optionalDevDependencies: false,
    peerDependencies: false,
};
var jsonfile = opts.p || opts.package || './package';

if (Array.isArray(jsonfile)) jsonfile = jsonfile[0];
if (jsonfile[0] !== '/') jsonfile = process.cwd() + '/' + jsonfile;

// TODO: refactor into a class NspCheck, and call the check(package, options, cb) on a singleton

var deps = getDepsOfJson(require(jsonfile), whichDeps, function(err, depsTree) {
    if (err) throw err;
    qhttp.post('https://registry.npmjs.org/-/npm/v1/security/audits', depsTree, function(err, res, body) {
        if (err) throw err;
        if (res.statusCode >= 400) throw new Error('http error getting audit: ' + res.statusCode);

        var report = tryJsonDecode(body);
        if (report instanceof Error) throw new Error('unable to decode audit: ' + body);
        var alerts = Object.keys(report.advisories);
//console.log("AR: Done. audit=", util.inspect(report, { depth: 6 }));

        // genreate the report
        qprintf.printf("found %d vulnerabilities\n", alerts.length);
        var rows = [];
        rows.push('--');
        for (var id in report.advisories) {
            var alert = report.advisories[id];
            rows.push([ toCapital(alert.severity) + ' ' + alert.metadata.exploitability, alert.title ]);
            for (var i=0; i<alert.findings.length; i++) {
            rows.push([ 'Package', alert.findings[i].paths.map(function(path){ return buildModulePath(depsTree, path.split('>')) }).join(' ') ]);
            }
            rows.push([ 'Occurs', alert.vulnerable_versions + ' (patched: ' + alert.patched_versions + ')' ]);
            // TODO: any reason to show all paths?
            // TODO: annotate the path with version numbers
            rows.push([ 'Info', alert.url + ' ' + alert.cves.join(',') + ' ' + alert.cwe ]);
            rows.push('--');
            // TODO: option to display more alert details (eg advisory messages, recommendations)
        }

        // format the report
        var colwid0 = 0, colwid1 = 0;
        for (var i=0; i<rows.length; i++) {
            if (rows[i] === '--') continue;
            rows[i][0] = String(rows[i][0]);
            rows[i][1] = String(rows[i][1]);
            if (rows[i][0].length > colwid0) colwid0 = rows[i][0].length;
            if (rows[i][1].length > colwid1) colwid1 = rows[i][1].length;
        }

        // print the report
        var dashes = str_repeat('-', colwid0 + colwid1 + 1);
        if (rows.length > 1) for (var i=0; i<rows.length; i++) {
            if (rows[i] === '--') {
                qprintf.printf("+-%.*s--+--%.*s-+\n", colwid0, dashes, colwid1, dashes);
            } else {
                qprintf.printf("| %-*s  |  %-*s |\n", colwid0, rows[i][0], colwid1, rows[i][1]);
            }
        }

        // let the process exitcode reflect vulnerability status: 0 = ok, 1 = vulnerable
        process.exit(rows.length > 1 ? 1 : 0);
    })
})

function toCapital( str ) {
    return str[0].toUpperCase() + str.slice(1);
}

function str_repeat( str, n ) {
    return str.repeat ? str.repeat(n) : new Array(n + 1).join(str);
}

function buildModulePath( depsTree, pathComponents ) {
    var names = [];
    while (pathComponents.length && depsTree) {
        var name = pathComponents.shift();
        names.push(name + '@' + depsTree.requires[name]);
        depsTree = depsTree.dependencies[name];
    }
    return names.reverse().join('  < ');
}

/**
 * given a package json pjson, return its dependencies
 * The returned object has properties { name, version, requires, dependencies }
 * where requires is the name:version mapping from the json file, and
 * dependencies is a recursive name:getDepsOfJson() mapping of the sub-dependencies.
 */
function getDepsOfJson( pjson, whichDeps, callback ) {
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

    // for each dependency, replace dependencies with the sub-deps object
    forEach(
        Object.keys(deps.requires),
        function(name, cb) {
            var version = deps.requires[name];

            getPJson(name, version, function(err, json) {
                if (err) return cb(err);
                if (!json) return cb(new Error('did not get a pjson object'));

                getDepsOfJson(json, whichDeps, function(err, subDeps) {
                    // assert subDeps.version == deps.requires[name]
                    deps.dependencies[name] = subDeps;
                    cb();
                })
            })
        },
        function(err) {
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

    function callback(err, ret) {
        userCallback(err, ret);
    }

    if (semverNumberRegex.test(version)) {
        var pjson = getCachedPJson(name, version);
        // TODO: option to bypass the cache, re-fetch everything
        if (pjson) { setImmediate(callback, null, pjson); return }

        qhttp.get('https://registry.npmjs.org/' + urlencode(name) + '/' + urlencode(version), function(err, res, body) {
            // nb: "GET is not allowed" MethodNotAllowedError means "not found" (eg '*' or '1.0')
            if (err) return callback(err);
            body = tryJsonDecode(String(body));
            if (body instanceof Error) return callback(new Error('unable to decode package.json: ' + body));
            callback(null, body);
        })
    }
    else if (/[://#]/.test(version)) {
// https://www.quora.com/How-can-I-pull-one-file-from-a-Git-repository-instead-of-the-entire-project
// git archive --format=tar --remote=ssh://{user}@{host}[:port]{/path/to/repo/on/filesystem} {tree-ish} -- {path to file in repo} |tar xf -
// or, for public repos (private repos return "404 Not Found"):
// curl https://raw.githubusercontent.com/andrasq/node-nsp-check/{{commit-ish, eg "master" or "0.13.2"}}/package.json
// TODO: parse url into host, user, repo, version, then reassemble:
        var repo = parseUserRepoVersion(version);
        if (!repo) throw new Error('unable to parse package path: ' + version);

        if (/^http/.test(repo.type)) {
            fetchRepoRawFile(repo, 'package.json', returnParsedPJson);
        }
        else if (/^git/.test(repo.type)) {
            fetchRepoGitFile(repo, 'package.json', returnParsedPJson);
        }
        else throw new Error(repo.type + ': repo type not handled yet');

        function returnParsedPJson( err, body ) {
            if (err) return callback(err);

            body = tryJsonDecode(String(body));
            if (body instanceof Error) return callback(new Error('unable to decode package.json: ' + body.message));

            callback(null, body);
        }
    }
    else {
// note: if the package version is not in npm, cannot query available versions
// TODO: only retrieve the package.json, not everything
// TODO: ? warn about under-constrained dependency
// FIXME: handle '*' and '>= 1.2' etc
        qhttp.get('https://registry.npmjs.org/' + urlencode(name), function(err, res, body) {
            if (err) return callback(err);
            body = tryJsonDecode(String(body));
            if (body instanceof Error) return callback(new Error('unable to decode response: ' + body));
            var bestVersion = selectBestVersion(Object.keys(body.versions), version);
            getPJson(name, bestVersion, callback);
        })
    }
}

function parseUserRepoVersion( str ) {
    var parts = Url.parse(str);
    if (!parts.slashes || !parts.path) return null;

// FIXME: retain parts.auth for http protocols (to be used for http basic auth)

    var nameSep = parts.path.indexOf('/', 1);
    if (!nameSep) return null;

    // Url.parse:
    //   git://git@github.com:andrasq/node-nsp-check#0.1.0 => { git: | github.com | /:andrasq/node-nsp-check | #0.1.0 }
    //   git+ssh://git@github.com:andrasq/node-nsp-check   => { git+ssh: | github.com | /:andrasq/node-nsp-check | null }
    //   https://github.com/andrasq/node-nsp-check#0.1.0   => { https: | github.com | /andrasq/node-nsp-check | #0.1.0 }

    var host = parts.host.toLowerCase();                // host, including port if any
    var version = parts.hash;                           // version if any, including leading #
    if (version[0] === '#') version = version.slice(1);
    if (!version) version = 'master';

    var repoOwner = parts.path.slice(1, nameSep);       // repo owner without leading /, but including a leading :
    if (repoOwner[0] === ':') repoOwner = repoOwner.slice(1);

    var repoName = parts.path.slice(nameSep + 1);       // repo name, without leading /
    if (repoName.slice(-1) === '/') repoName = repoName.slice(0, -1);
    if (repoName.slice(-4) === '.git') repoName = repoName.slice(0, -4);

    if (!host || !repoOwner || !repoName) return null;

    var type = /http/.test(parts.protocol) ? 'http' : /git/.test(parts.protocol) ? 'git' : null;
    if (/ssh/.test(parts.protocol)) type += '+ssh';

    var ret = {
        // TODO: maybe expose not type but { proto: proto.toLowerCase() }
        type: type, host: host, user: repoOwner, repo: repoName, version: version,
        input: str,
    };
    return ret;
}

function fetchRepoRawFile( repo, filename, callback ) {
    if (repo.host === 'github.com' || repo.host === 'github.com:80') {
        var url = qprintf.sprintf("https://raw.githubusercontent.com/%s/%s/%s/%s", repo.user, repo.repo, repo.version, filename);
        qhttp.get(url, returnCb);
        // TODO: if not found, try with github credentials
    }
    // TODO: gitlab.com etc other git-like repos
    // TODO: repos with other path syntaxes
    else {
        var url = qprintf.sprintf("https://%s/%s/%s/%s/%s", repo.host, repo.user, repo.repo, repo.version, filename);
        qhttp.get(url, returnCb);
    }

    function returnCb( err, res, body ) {
        if (err || res.statusCode >= 300) return callback(err || new Error('error fetching file: http ' + res.statusCode));
        callback(null, String(body));
    }
}

// fetch file with git protocol
function fetchRepoGitFile( repo, filename, callback ) {
    // FIXME: use git credentials to be able to access private repos too
    if (repo.host === 'github.com' || repo.host === 'github.com:80') {
        var url = qprintf.sprintf("https://raw.githubusercontent.com/%s/%s/%s/%s", repo.user, repo.repo, repo.version, filename);
    } else {
        // TODO: handle repos with other path syntaxes
        var url = qprintf.sprintf("https://%s/%s/%s/%s/%s", repo.host, repo.user, repo.repo, repo.version, filename);
    }
    qhttp.get(url, function(err, res, body) {
        if (err || res.statusCode >= 400) return callback(err || new Error('unable to fetch file: http ' + res.statusCode));
        callback(null, String(body));
    })
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
