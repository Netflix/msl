(function () {
    // Check if typed arrays are supported
    if (typeof ArrayBuffer != 'function' && typeof ArrayBuffer != 'object') {
        return;
    }

    // Shortcuts
    var C = CryptoJS;
    var C_lib = C.lib;
    var WordArray = C_lib.WordArray;

    // Reference original init
    var $superInit = WordArray.init;

    // Augment WordArray.init to handle typed arrays
    WordArray.init = function (typedArray) {
        // Convert buffers to data view
        if (typedArray instanceof ArrayBuffer) {
            if (typeof DataView == 'undefined') {
                typedArray = new Uint8Array(typedArray);
            } else {                
                typedArray = new DataView(typedArray);
            }
        }

        // Convert array views to data view
        if (
            typedArray instanceof Int8Array ||
            typedArray instanceof Uint8Array ||
            typedArray instanceof Uint8ClampedArray ||
            typedArray instanceof Int16Array ||
            typedArray instanceof Uint16Array ||
            typedArray instanceof Int32Array ||
            typedArray instanceof Uint32Array ||
            typedArray instanceof Float32Array ||
            typedArray instanceof Float64Array ) 
        {
            if (typeof DataView == 'undefined') {
                if (!(typedArray instanceof Uint8Array || typedArray instanceof Uint8ClampedArray)) {
                    throw new Error('With no DataView, we can only handle Uint8 arrays');
                }
            } else {
                typedArray = new DataView(typedArray.buffer);
            }
        }

        if (typedArray instanceof Uint8Array || typedArray instanceof Uint8ClampedArray) {
            var typedArrayByteLength = typedArray.length;

            var words = [];
            for (var i = 0; i < typedArrayByteLength; i++) {
                words[i >>> 2] |= typedArray[i] << (24 - (i % 4) * 8);
            }
            $superInit.call(this, words, typedArrayByteLength);
            return;
        } 

        if (typeof DataView != 'undefined' && typedArray instanceof DataView) {
            var typedArrayByteLength = typedArray.byteLength;

            var words = [];
            for (var i = 0; i < typedArrayByteLength; i++) {
                words[i >>> 2] |= typedArray.getUint8(i) << (24 - (i % 4) * 8);
            }

            $superInit.call(this, words, typedArrayByteLength);
            return;
        } 
        
        // Else call normal init
        $superInit.apply(this, arguments);        
    };
    
    // Add WordArray.arrayify to convert to Uint8Array.
    WordArray.arrayify = function () {
    	var byteLength = this.sigBytes;
    	
    	var buffer = new ArrayBuffer(byteLength);
        if (typeof DataView == 'undefined') {
            var typedArray = new Uint8Array(buffer);
            for (var i = 0; i < byteLength; ++i) {
                typedArray[i] = this.words[i >>> 2] >> (24 - (i % 4) * 8);
            }
            return typedArray;
        }
    	var typedArray = new DataView(buffer);
    	for (var i = 0; i < byteLength; ++i) {
    		typedArray.setUint8(i, this.words[i >>> 2] >> (24 - (i % 4) * 8));
    	}
    	return new Uint8Array(typedArray.buffer);
    };
}());
