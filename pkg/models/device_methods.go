package models

// HasOpenPort checks if the device has the specified port open
func (d *Device) HasOpenPort(port int) bool {
	_, exists := d.OpenPorts[port]
	return exists
}
