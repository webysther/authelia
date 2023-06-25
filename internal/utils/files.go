package utils

import (
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"syscall"
)

// FileExists returns true if the given path exists and is a file.
func FileExists(path string) (exists bool, err error) {
	info, err := os.Stat(path)
	if err == nil {
		if info.IsDir() {
			return false, errors.New("path is a directory")
		}

		return true, nil
	}

	if os.IsNotExist(err) {
		return false, nil
	}

	return false, err
}

// DirectoryExists returns true if the given path exists and is a directory.
func DirectoryExists(path string) (exists bool, err error) {
	info, err := os.Stat(path)
	if err == nil {
		if info.IsDir() {
			return true, nil
		}

		return false, errors.New("path is a file")
	}

	if os.IsNotExist(err) {
		return false, nil
	}

	return false, err
}

// PathExists returns true if the given path exists.
func PathExists(path string) (exists bool, err error) {
	_, err = os.Stat(path)
	if err == nil {
		return true, nil
	}

	if os.IsNotExist(err) {
		return false, nil
	}

	return true, err
}

func NewReadOnlyOpenFile(name string) (file *OpenFile, err error) {
	return NewOpenFile(name, os.O_RDONLY, 0)
}

func NewOpenFile(name string, flag int, perm os.FileMode) (file *OpenFile, err error) {
	file = &OpenFile{
		name: name,
		flag: flag,
		perm: perm,
		mu:   &sync.Mutex{},
	}

	if err = file.open(); err != nil {
		return nil, err
	}

	return file, nil
}

// OpenFile is an extension on os.File which can be locked and various other things.
type OpenFile struct {
	*os.File

	name string
	flag int
	perm os.FileMode

	mu     *sync.Mutex
	locked bool
}

func (f *OpenFile) Close() (err error) {
	return f.close(true)
}

func (f *OpenFile) WaitClose() (err error) {
	return f.close(false)
}

func (f *OpenFile) close(nb bool) (err error) {
	if err = f.unlock(nb); err != nil {
		return err
	}

	f.mu.Lock()

	defer f.mu.Unlock()

	if err = f.File.Close(); err != nil {
		return err
	}

	f.File = nil

	return nil
}

func (f *OpenFile) Unlock() (err error) {
	return f.unlock(true)
}

func (f *OpenFile) WaitUnlock() (err error) {
	return f.unlock(false)
}

func (f *OpenFile) Lock() (err error) {
	if _, err = f.lock(syscall.LOCK_EX, true); err != nil {
		return err
	}

	return nil
}

func (f *OpenFile) WaitLock() (err error) {
	if _, err = f.lock(syscall.LOCK_EX, false); err != nil {
		return err
	}

	return nil
}

// Open the file. This not a thread safe operation and thread safety should be managed by the caller.
func (f *OpenFile) open() (err error) {
	var file *os.File

	if file, err = os.OpenFile(f.name, f.flag, f.perm); err != nil {
		return err
	}

	f.File = file

	return nil
}

func (f *OpenFile) unlock(nb bool) (err error) {
	f.mu.Lock()

	defer f.mu.Unlock()

	if !f.locked || f.File == nil {
		fmt.Println("skip unlock")

		return nil
	}

	flag, cmd := syscall.LOCK_UN, syscall.F_SETLKW

	if nb {
		flag |= syscall.LOCK_NB
		cmd = syscall.F_SETLK
	}

	fmt.Println("performing flock (unlock)")

	if err = syscall.Flock(int(f.File.Fd()), syscall.LOCK_UN); err != nil {
		return err
	}

	fmt.Println("performing fcntl (unlock)")

	if err = syscall.FcntlFlock(f.File.Fd(), cmd, &syscall.Flock_t{Start: 0, Len: 0, Type: syscall.F_UNLCK, Whence: io.SeekStart}); err != nil {
		return err
	}

	f.locked = false

	return nil
}

func (f *OpenFile) lock(flag int, nb bool) (locked bool, err error) {
	f.mu.Lock()

	defer f.mu.Unlock()

	if f.locked {
		fmt.Println("already locked")

		return true, nil
	}

	if f.File == nil {
		if err = f.open(); err != nil {
			return false, &os.PathError{Op: "flock", Path: f.name, Err: err}
		}
	}

	cmd, lt := syscall.F_SETLKW, int16(syscall.F_WRLCK)

	if nb {
		flag = flag | syscall.LOCK_NB
		cmd = syscall.F_SETLK
	}

	if flag&os.O_RDONLY != 0 {
		lt = syscall.F_RDLCK
	}

	var retried bool

retryAdvisory:
	fmt.Println("performing flock")

	switch err = syscall.Flock(int(f.File.Fd()), flag); {
	case err == nil:
		fmt.Println("no error")

		break
	case err == syscall.EWOULDBLOCK:
		fmt.Println("would block")
		return false, nil
	default:
		fmt.Println("retry")

		if retried {
			return false, &os.PathError{Op: "flock", Path: f.name, Err: err}
		}

		reopened, reopenErr := f.reopenErr(err)

		if reopenErr != nil {
			return false, &os.PathError{Op: "flock", Path: f.name, Err: reopenErr}
		}

		if !reopened {
			return false, &os.PathError{Op: "flock", Path: f.name, Err: err}
		}

		retried = true

		goto retryAdvisory
	}

	fmt.Println(cmd)

retryMandatory:
	fmt.Println("performing fcntl flock")

	switch err = syscall.FcntlFlock(f.File.Fd(), cmd, &syscall.Flock_t{Start: 0, Len: 0, Type: lt, Whence: io.SeekStart}); {
	case err == nil:
		fmt.Println("no error")

		break
	case err == syscall.EWOULDBLOCK:
		fmt.Println("would block")
		return false, nil
	default:
		fmt.Println("retry")

		if retried {
			return false, &os.PathError{Op: "fcntl", Path: f.name, Err: err}
		}

		reopened, reopenErr := f.reopenErr(err)

		if reopenErr != nil {
			return false, &os.PathError{Op: "fcntl", Path: f.name, Err: reopenErr}
		}

		if !reopened {
			return false, &os.PathError{Op: "fcntl", Path: f.name, Err: err}
		}

		retried = true

		goto retryMandatory
	}

	fmt.Println("flock success")

	f.locked = true

	return true, nil
}

func (f *OpenFile) reopenErr(e error) (reopened bool, err error) {
	switch e {
	case syscall.EIO, syscall.EBADF:
		var stat os.FileInfo

		if stat, err = f.File.Stat(); err != nil {
			return false, nil
		}

		if stat.Mode()&f.perm != f.perm {
			return false, nil
		}

		_ = f.File.Close()
		f.File = nil

		if err = f.open(); err != nil {
			return false, err
		}

		return true, nil
	default:
		return false, nil
	}
}
