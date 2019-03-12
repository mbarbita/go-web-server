  window.addEventListener("load", function(evtArd) {
    var outputArd = document.getElementById("output-ard");
    // var input = document.getElementById("input");
    var messageMap = new Map();
    var wsArd;

var drawArd = function(message) {
  // var dArd = document.createElement("div");
  // dArd.innerHTML = i + " RESPONSE: " + message;
  // dArd.style.backgroundColor = 'green';
  var fields = message.split(";");

  // var fields2;
  for (let value of fields) {
    // console.log(value);
    var fields2 = value.split(" ");
    // console.log(fields2);
    messageMap.set(fields2[0],fields2[1]);
    // console.log(messageMap);
  };
  messageMap.delete("");

  // var fields2 = fields[0].split(" ");
  // messageMap.set(fields2[0],fields2[1]);
  // dArd.innerHTML = fields[0]+fields[1]+fields[2];

};

    var printArd = function(message,i) {

for (var value of messageMap.values()) {
  var dArd = document.createElement("div");
  dArd.style.backgroundColor = 'green';
  dArd.innerHTML = value;
  console.log(value);
  outputArd.appendChild(dArd);
};
      // dArd.innerHTML = messageMap.get(fields2[0]);
      // outputArd.appendChild(dArd);
    };

    // printArd("Test");
    document.getElementById("open-ard").onclick = function(evtArd) {
      document.getElementById("output-ard").innerHTML = "";
      var i = 0;
      if (wsArd) {
        return false;
      }
      wsArd = new WebSocket("ws://{{index . 0}}/msgard/");
      wsArd.onopen = function(evtArd) {
        console.log("OPEN");
        // printArd("OPEN");
        // printArd("ws://{{index . 0}}/msgard/");
        // ws.send("OPEN");
      }
      wsArd.onclose = function(evtArd) {
        console.log("CLOSE");
        // printArd("CLOSE");
        wsArd = null;
      }
      wsArd.onmessage = function(evtArd) {
        if (i % 3 == 0) {
          // document.getElementById("output").innerHTML = "";
          outputArd.innerHTML = "";
          // i = 0;
        }
        i++
        drawArd(evtArd.data);
        printArd(evtArd.data,i);
      }
      wsArd.onerror = function(evtArd) {
        console.log("ERROR: " + evtArd.data);
        // printArd("ERROR: " + evtArd.data);
      }
      return false;
    };
    // document.getElementById("send").onclick = function(evt) {
    //   if (!ws) {
    //     return false;
    //   }
    //   print("SEND: " + input.value);
    //   ws.send(input.value);
    //   return false;
    // };
    document.getElementById("close-ard").onclick = function(evtArd) {
      if (!wsArd) {
        return false;
      }
      wsArd.close();
      return false;
    };
  });
