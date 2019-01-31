#$env:GOOS="linux"
#$env:GOARCH="arm"
#$env:GOARM="7"

$osArray = "windows","linux"
$archArray = "386","amd64"
foreach ($os in $osArray)
{
foreach ($arch in $archArray)
{
	echo "compile: "$os"-"$arch
	$env:GOOS=$os
	$env:GOARCH=$arch

go build -o $env:GOOS"-"$env:GOARCH
}
}
