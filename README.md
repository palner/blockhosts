# Blockhosts

Log parser / blocker using Golang and IPtables.

## Installing

1. Make sure you have iptables installed on your system
2. Download the binary to `/usr/local/bin/`
3. Download the config to `/usr/local/bin/`
4. Update hosts.deny
5. Enjoy

You can also do the Super Lazy install of:

`curl -sSL https://raw.githubusercontent.com/palner/blockhosts/refs/heads/main/install_blockhosts.sh | bash`

_If you do the super lazy install, please check the `/etc/hosts.deny` for accuracy as well as adding your IP to `/usr/local/bin/bhconfig.json`._

## Details

### Downloading the binary

```
cd /usr/local/bin
wget https://github.com/palner/blockhosts/raw/refs/heads/main/binary/blockhosts
chmod +x blockhosts
```

### Download the config

```
cd /usr/local/bin
wget https://raw.githubusercontent.com/palner/blockhosts/refs/heads/main/bhconfig.json
```

#### Update the config

There is a section (in `json`) called **Allowed**. Add your CIDRs as desired.

Examples...

```json
"Allowed": [{"cidr":"192.168.0.3/32"}]
```

```json
"Allowed": [{"cidr":"192.168.0.0/16"},{"cidr":"1.1.1.1/32"},{"cidr":"10.0.10.0/24"}]
```

```json
"Allowed": [{"cidr":"192.168.0.0/16"}]
```

### Update hosts.deny

Examples:

#### Debian/Ubuntu or boxes using /var/log/auth.log

```
#
# hosts.deny	This file describes the names of the hosts which are
#		*not* allowed to use the local INET services, as decided
#		by the '/usr/sbin/tcpd' server.
#

sshd : ALL : spawn (/usr/local/bin/blockhosts) : allow
sshd : ALL : allow
```

#### CentOS or boxes using /var/log/secure

```
#
# hosts.deny	This file describes the names of the hosts which are
#		*not* allowed to use the local INET services, as decided
#		by the '/usr/sbin/tcpd' server.
#

sshd : ALL : spawn (/usr/local/bin/blockhosts -ssh=/var/log/secure) : allow
sshd : ALL : allow
```

## Other Flags

- `ssh`: log file to parse
- `target`: iptables action (default is `DROP`)
- `chain`: iptables chain name (default is `APIBANLOCAL`) (Note: will be created if it doesn't exist)
- `log`: log file for output (default is /var/log/blockhosts.log)
- `xtra`: `true|false`. default false. Used for extra logging
- `full`: `true|false`. default false. Read full log (vs 5000 line chunks)

Example:

`/usr/local/bin/blockhosts -ssh=/var/log/secure -xtra=true -chain=SSHCHAIN -target=REJECT`

## License / Warranty

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

See LICENSE for more details

## Thanks

Like it? Please star and consider a [sponsor](https://github.com/sponsors/palner)