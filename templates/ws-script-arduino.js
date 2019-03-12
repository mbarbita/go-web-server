  window.addEventListener("load", function(evtArd) {
    var outputArd = document.getElementById("output-ard");
    // var input = document.getElementById("input");
    var wsArd;
    var printArd = function(message) {
      var dArd = document.createElement("div");
      dArd.innerHTML = message;
      outputArd.appendChild(dArd);
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
        printArd("OPEN");
        // printArd("ws://{{index . 0}}/msgard/");
        // ws.send("OPEN");
      }
      wsArd.onclose = function(evtArd) {
        printArd("CLOSE");
        wsArd = null;
      }
      wsArd.onmessage = function(evtArd) {
        if (i % 10 == 0) {
          // document.getElementById("output").innerHTML = "";
          outputArd.innerHTML = "";
          // i = 0;
        }
        i++
        printArd(i + " RESPONSE: " + evtArd.data);
      }
      wsArd.onerror = function(evtArd) {
        printArd("ERROR: " + evtArd.data);
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
