package allowmutations

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"sync"

	"github.com/containerd/nri/pkg/adaptation/builtin"
	"github.com/containerd/nri/pkg/api"
	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

// this is default config path for allowmuatations.

const (
	DefaultConfigPath = "/etc/crio/nri_plugins/AllowMutations/config.yaml"
)

var ErrMutationRejected = errors.New("NRI mutation rejected")

// Config is loaded from the external YAML file.
type Config struct {
	AllowedNamespaces []string `yaml:"allowedNamespaces"`
}

// AllowMutationsConfig is the CRI-O crio.conf configuration for this plugin.
type AllowMutationsConfig struct {
	Enable     bool   `toml:"nri_enable_allow_mutations"`
	ConfigPath string `toml:"nri_allow_mutations_config_path"`
}

// Plugin validates NRI container adjustments against a namespace allowlist.
type Plugin struct {
	mu     sync.RWMutex
	config Config
}

func NewPlugin(configPath string) (*Plugin, error) {
	p := &Plugin{}
	if err := p.loadConfig(configPath); err != nil {
		return nil, err
	}
	return p, nil
}

func (p *Plugin) loadConfig(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read AllowMutations config %s: %w", path, err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return fmt.Errorf("parse AllowMutations config %s: %w", path, err)
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	p.config = cfg

	return nil
}

// ValidateContainerAdjustment rejects mutations for containers whose pod
// namespace is not in the configured allowlist.
func (p *Plugin) ValidateContainerAdjustment(ctx context.Context, req *api.ValidateContainerAdjustmentRequest) error {
	if req.Adjust == nil {
		return nil
	}

	namespace := req.GetPod().GetNamespace()
	podName := req.GetPod().GetName()
	containerName := req.GetContainer().GetName()

	p.mu.RLock()
	allowed := slices.Contains(p.config.AllowedNamespaces, namespace)
	p.mu.RUnlock()

	if allowed {
		logrus.Debugf("AllowMutations: allowing mutations for %s/%s/%s",
			namespace, podName, containerName)
		return nil
	}

	return fmt.Errorf("%w: namespace %q is not in the allowed list for %s/%s",
		ErrMutationRejected, namespace, podName, containerName)
}

// GetBuiltinPlugin returns a configured builtin NRI plugin instance.
// Returns nil if disabled or if config loading fails.
func GetBuiltinPlugin(cfg *AllowMutationsConfig) *builtin.BuiltinPlugin {
	if cfg == nil || !cfg.Enable {
		logrus.Info("built-in NRI AllowMutations plugin is disabled")
		return nil
	}

	configPath := cfg.ConfigPath
	if configPath == "" {
		configPath = DefaultConfigPath
	}

	p, err := NewPlugin(configPath)
	if err != nil {
		logrus.Errorf("Failed to initialize AllowMutations plugin: %v", err)
		return nil
	}

	logrus.Infof("AllowMutations plugin loaded, allowed namespaces: %v",
		p.config.AllowedNamespaces)

	return &builtin.BuiltinPlugin{
		Base:  "allow-mutations",
		Index: "99",
		Handlers: builtin.BuiltinHandlers{
			ValidateContainerAdjustment: p.ValidateContainerAdjustment,
		},
	}
}
