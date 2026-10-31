package workloadresource

import (
	"context"
	"net/http"
	"strings"
)

// OperationResolver derives a trusted operation from the resource's own
// routing/persistence layer. It must NEVER accept a token-supplied Tenant,
// Organisation, Market or business entitlement as authoritative context.
type OperationResolver interface {
	ResolveOperation(context.Context, *http.Request) (Operation, error)
}

// Middleware enforces the same provider-neutral gate at a real HTTP resource
// boundary, forwarding only after fresh issuer + CP + native checks. Tokens
// are intentionally stripped from downstream handler headers.
type Middleware struct {
	gate ResourceAuthorizer
	operations OperationResolver
	next http.Handler
}

// The public HTTP fence must never accept an arbitrary implementation
// that can return nil without verifying a signed issuer token. Only the
// audited N03 Gate and the N04 RegisteredGate wrapping that exact Gate are
// admissible. Internal fakes remain confined to non-HTTP unit helpers.
func trustedHTTPAuthorizer(value ResourceAuthorizer) bool {
	switch gate := value.(type) {
	case *Gate:
		return gate != nil
	case *RegisteredGate:
		if gate == nil || absent(gate.provider) {
			return false
		}
		native, ok := gate.resource.(*Gate)
		return ok && native != nil
	default:
		return false
	}
}

func NewMiddleware(gate ResourceAuthorizer, operations OperationResolver, next http.Handler) (*Middleware, error) {
	if !trustedHTTPAuthorizer(gate) || absent(operations) || absent(next) {
		return nil, ErrDenied
	}
	return &Middleware{gate: gate, operations: operations, next: next}, nil
}

func singleBearer(r *http.Request) (string, error) {
	if r == nil {return "", ErrDenied}
	values:=r.Header.Values("Authorization")
	if len(values)!=1 || len(values[0])>16391{return "",ErrDenied}
	v:=values[0]
	if len(v)<27 || !strings.EqualFold(v[:7],"Bearer "){return "",ErrDenied}
	token:=v[7:]
	if len(token)<20||len(token)>16384||strings.TrimSpace(token)!=token||
		strings.ContainsAny(token," \t\r\n,"){return "",ErrDenied}
	return token,nil
}
func (m *Middleware) ServeHTTP(w http.ResponseWriter,r *http.Request) {
	w.Header().Set("Cache-Control","no-store")
	w.Header().Set("Pragma","no-cache")
	w.Header().Set("X-Content-Type-Options","nosniff")
	if m==nil||absent(m.gate)||r==nil {
		http.Error(w,"Unauthorized",http.StatusUnauthorized)
		return
	}
	raw,err:=singleBearer(r)
	if err!=nil {http.Error(w,"Unauthorized",http.StatusUnauthorized);return}
	op,err:=m.operations.ResolveOperation(r.Context(),r)
	if err!=nil || m.gate.Authorize(r.Context(),raw,op)!=nil {
		// External response is deliberately uniform; issuer outage and CP
		// denial are never a successful fallback or a token leak.
		http.Error(w,"Forbidden",http.StatusForbidden)
		return
	}
	// Do not pass the workload's raw bearer or cookie into native application
	// handlers. The owning operation policy already received signed evidence.
	clean:=r.Clone(r.Context())
	clean.Header=clean.Header.Clone()
	clean.Header.Del("Authorization")
	clean.Header.Del("Cookie")
	m.next.ServeHTTP(w,clean)
}
var _ http.Handler = (*Middleware)(nil)
