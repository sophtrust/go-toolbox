module go.sophtrust.dev/pkg/toolbox

go 1.16

require (
	github.com/BurntSushi/toml v0.4.1
	github.com/ProtonMail/gopenpgp/v2 v2.2.2
	github.com/gin-gonic/gin v1.7.7
	github.com/go-playground/locales v0.14.0
	github.com/go-playground/universal-translator v0.18.0
	github.com/go-redis/redis/v8 v8.3.4
	github.com/go-redis/redis_rate/v9 v9.1.1
	github.com/golang-jwt/jwt/v4 v4.0.0
	github.com/google/uuid v1.1.2
	github.com/ip2location/ip2location-go/v9 v9.1.0
	github.com/stretchr/testify v1.7.1-0.20210427113832-6241f9ab9942 // indirect
	go.sophtrust.dev/pkg/zerolog/v2 v2.0.0
	golang.org/x/net v0.0.0-20210805182204-aaa1db679c0d
	golang.org/x/text v0.3.6
	gopkg.in/yaml.v2 v2.4.0
	k8s.io/apimachinery v0.22.1
	k8s.io/client-go v0.22.1
)

replace go.sophtrust.dev/pkg/zerolog/v2 => /Users/joshhogle/workspace/src/github.com/sophtrust/go-zerolog
