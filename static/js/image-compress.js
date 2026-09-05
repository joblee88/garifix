/*
 * image-compress.js - Inapunguza ukubwa wa picha NDANI YA SIMU/BROWSER
 * KABLA ya kuipakia (upload), kwa kutumia HTML5 Canvas. Hii inasaidia:
 *   1. Kupunguza MUDA wa kupakia (hasa kwa mtandao dhaifu - muhimu Tanzania)
 *   2. Kupunguza DATA (MB) inayotumika kupakia
 *   3. Kuepuka "413 Payload Too Large" kwenye faili kubwa mno
 *
 * JINSI YA KUTUMIA: ongeza atribute "data-compress" kwenye <input type=file>
 * yoyote, kisha piga simu setupGariFixImageCompression() mara moja kwenye
 * ukurasa. Kila mtumiaji akichagua picha, inabanwa kiotomatiki kabla ya
 * form kutumwa.
 */
function compressGariFixImage(file, maxDimension, quality) {
    return new Promise(function (resolve) {
        // Faili zisizo picha (au tayari ndogo sana) hazihitaji kubanwa
        if (!file.type.startsWith("image/") || file.size < 300 * 1024) {
            resolve(file);
            return;
        }

        var reader = new FileReader();
        reader.onload = function (e) {
            var img = new Image();
            img.onload = function () {
                var canvas = document.createElement("canvas");
                var width = img.width;
                var height = img.height;

                if (width > height && width > maxDimension) {
                    height = Math.round((height * maxDimension) / width);
                    width = maxDimension;
                } else if (height > maxDimension) {
                    width = Math.round((width * maxDimension) / height);
                    height = maxDimension;
                }

                canvas.width = width;
                canvas.height = height;
                var ctx = canvas.getContext("2d");
                ctx.drawImage(img, 0, 0, width, height);

                canvas.toBlob(
                    function (blob) {
                        if (!blob) {
                            resolve(file);
                            return;
                        }
                        var compressedFile = new File([blob], file.name, {
                            type: "image/jpeg",
                            lastModified: Date.now(),
                        });
                        resolve(compressedFile);
                    },
                    "image/jpeg",
                    quality
                );
            };
            img.onerror = function () {
                resolve(file);
            };
            img.src = e.target.result;
        };
        reader.onerror = function () {
            resolve(file);
        };
        reader.readAsDataURL(file);
    });
}

function setupGariFixImageCompression() {
    var inputs = document.querySelectorAll('input[type="file"][data-compress]');

    inputs.forEach(function (input) {
        input.addEventListener("change", function (event) {
            var files = event.target.files;
            if (!files || files.length === 0) return;

            var maxDim = parseInt(input.getAttribute("data-compress-max") || "1280", 10);
            var quality = parseFloat(input.getAttribute("data-compress-quality") || "0.75");

            var compressPromises = [];
            for (var i = 0; i < files.length; i++) {
                compressPromises.push(compressGariFixImage(files[i], maxDim, quality));
            }

            Promise.all(compressPromises).then(function (compressedFiles) {
                var dataTransfer = new DataTransfer();
                compressedFiles.forEach(function (f) {
                    dataTransfer.items.add(f);
                });
                input.files = dataTransfer.files;
            });
        });
    });
}

document.addEventListener("DOMContentLoaded", setupGariFixImageCompression);
