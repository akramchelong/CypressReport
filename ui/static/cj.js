if (self === top) {
  // self === top means that the window is not a frame/iframe
  var antiClickjack = document.getElementById("antiClickjack");
  antiClickjack.parentNode.removeChild(antiClickjack);
} else {
  top.location = self.location;
}
