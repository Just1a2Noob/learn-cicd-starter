package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	type args struct {
		headers http.Header
		api_key string
	}
	tests := []struct {
		name   string
		args   args
		want   string
		errVal error
	}{
		{
			name: "Success on getting API Key",
			args: args{
				headers: make(http.Header),
				api_key: "ApiKey SECRET_API_KEY",
			},
			want: "SECRET_API_KEY",
		},
		{
			name: "No Authorization Header",
			args: args{
				headers: make(http.Header),
			},
			want:   "",
			errVal: ErrNoAuthHeaderIncluded,
		},
		{
			name: "Malformed Auth Header",
			args: args{
				headers: make(http.Header),
				api_key: "Bearer SECRET_API_KEY",
			},
			want:   "",
			errVal: ErrMalformedHeader,
		},
		{
			name: "Header string too long",
			args: args{
				headers: make(http.Header),
				api_key: "Bearer SECRET_API_KEY IMPORTANT_TEXT",
			},
			want:   "",
			errVal: ErrMalformedHeader,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.args.headers.Set("Authorization", tt.args.api_key)
			got, err := GetAPIKey(tt.args.headers)
			if err != nil && err != ErrNoAuthHeaderIncluded {
				if errors.Is(err, tt.errVal) != true {
					t.Errorf("GetAPIKey() error = %v", err)
					return
				}
			}
			if got != tt.want {
				t.Errorf("GetAPIKey() = %v, want %v", got, tt.want)
			}
		})
	}
}
