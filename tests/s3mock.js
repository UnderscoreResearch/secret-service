'use strict';

var existingFiles = {};

module.exports.setFiles = function(files) {
    existingFiles = files;
}

module.exports.getFiles = function(files) {
    return existingFiles;
}

function convertMetadataKeys(data) {
    if (data.Metadata) {
        var metadata = {};
        for (var i in data.Metadata) {
            metadata[i.toLowerCase()] = data.Metadata[i];
            
            if (!data.Metadata[i]) {
                throw new Error("Empty metadata: " + i);
            }
            if (typeof data.Metadata[i] !== 'string') {
                throw new Error("Tried to save non string metadata " + i + "=" + data.Metadata[i]);
            }
        }
        data.Metadata = metadata;
    }
    return data;
}

module.exports.getObject = function(file, callback) {
    var file = existingFiles[file.Key];
    if (file) {
        callback(null, convertMetadataKeys(Object.assign({}, file)));
    } else {
        callback({ code: "NoSuchKey" }, file);
    }
}

module.exports.headObject = function(file, callback) {
    var file = existingFiles[file.Key];
    if (file) {
        var ret = convertMetadataKeys(Object.assign({}, file));
        delete ret["Body"];
        callback(null, ret);
    } else {
        callback({ code: "NoSuchKey" }, file);
    }
}

module.exports.putObject = function(file, callback) {
    if (existingFiles) {

        existingFiles[file.Key] = Object.assign({}, file);
        callback(null, file);
    } else {
        callback("Can't put");
    }
}

module.exports.listObjectsV2 = function(file, callback) {
    if (existingFiles) {
        var data = [];
        Object.keys(existingFiles).forEach(function(f) {
            if (f.startsWith(file.Prefix)) {
                data.push(Object.assign({}, existingFiles[f]));
            }
        });
        callback(null, {
            "Contents": data
        });
    } else {
        callback("Can't list");
    }
}

module.exports.deleteObjects = function(files, callback) {
    if (existingFiles) {
        files.Delete.Objects.forEach(function(f) {
            delete existingFiles[f.Key];
        });
        callback(null);
    } else {
        callback("Can't delete");
    }
}