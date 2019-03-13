window.addEventListener("load", function(evtArd) {
    var outputArd = document.getElementById("output-ard");
    var messageMap = new Map();
    var wsArd;

    var drawArd = function() {
        outputArd.innerHTML = "";

        for (var [key, value] of messageMap) {
          var fields = value.split(" ");
          console.log(fields)
            var dArd = document.createElement("div");
            switch (fields[0]) {
                case "-2":
                    dArd.style.backgroundColor = 'gray';
                    dArd.innerHTML = key + " TIMEOUT, last seen: "+ fields[1];
                    break;
                case "-1":
                    dArd.style.backgroundColor = 'red';
                    dArd.innerHTML = key + " TROUBLE";
                    break;
                default:
                    dArd.style.backgroundColor = 'green';
                    dArd.innerHTML = key + " " + value;
            }
            // console.log(key, value);
            outputArd.appendChild(dArd);
        };
    };

    document.getElementById("open-ard").onclick = function(evtArd) {
        document.getElementById("output-ard").innerHTML = "";
        var i = 0;
        if (wsArd) {
            return false;
        }
        wsArd = new WebSocket("ws://{{index . 0}}/msgard/");
        wsArd.onopen = function(evtArd) {
            console.log("OPEN");
        }

        wsArd.onclose = function(evtArd) {
            console.log("CLOSE");
            wsArd = null;
        }

        wsArd.onmessage = function(evtArd) {
            console.log("MESSAGE:");
            console.log(evtArd.data);

            if (i % 3 == 0) {
                outputArd.innerHTML = "";
            }

            var fields = evtArd.data.split(";");
            for (let value of fields) {
                var fields2 = value.split(" ");
                messageMap.set(fields2[0], fields2[1]+" "+ fields2[2]);
            };
            messageMap.delete("");

            i++
            drawArd();
        }

        wsArd.onerror = function(evtArd) {
            console.log("ERROR: " + evtArd.data);
        }
        return false;
    };

    document.getElementById("close-ard").onclick = function(evtArd) {
        if (!wsArd) {
            return false;
        }
        wsArd.close();
        return false;
    };
});
