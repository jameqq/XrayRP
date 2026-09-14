package versioninfo

import "runtime/debug"

type Dependencies struct {
	XrayCore string
	Hysteria string
	SingBox  string
}

func Current() Dependencies {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return Dependencies{}
	}
	return fromBuildInfo(info)
}

func fromBuildInfo(info *debug.BuildInfo) Dependencies {
	return Dependencies{
		XrayCore: moduleVersion(info, "github.com/xtls/xray-core"),
		Hysteria: moduleVersion(info, "github.com/apernet/hysteria/core/v2"),
		SingBox:  moduleVersion(info, "github.com/sagernet/sing-box"),
	}
}

func moduleVersion(info *debug.BuildInfo, path string) string {
	for _, dependency := range info.Deps {
		if dependency.Path != path {
			continue
		}
		if dependency.Replace != nil && dependency.Replace.Version != "" {
			return dependency.Replace.Version
		}
		return dependency.Version
	}
	return ""
}
