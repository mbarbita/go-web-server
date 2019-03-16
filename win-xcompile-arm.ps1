$pre="server-"
$env:GOOS="linux"
$env:GOARCH="arm"
$env:GOARM="7"

go build -o $pre$env:GOOS"-"$env:GOARCH"-"$env:GOARM
