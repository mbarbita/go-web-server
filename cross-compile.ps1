$archArray = "386","amd64"

foreach ($arch in $archArray)
{
	$pre="go-web-server-"
	
	$os="windows"
	$env:GOOS=$os
	$env:GOARCH=$arch
	echo "compile: "$os"-"$arch
	go build -o $pre$env:GOOS"-"$env:GOARCH".exe"

	$os="linux"
	$env:GOOS=$os
	$env:GOARCH=$arch
	echo "compile: "$os"-"$arch
	go build -o $pre$env:GOOS"-"$env:GOARCH
}
