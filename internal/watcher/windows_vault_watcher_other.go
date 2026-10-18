//go:build !windows

package watcher

import "context"

func (w *Watcher) startPlatformAccountWatcher(_ context.Context) {}
