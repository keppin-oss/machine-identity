// Package identity centralises the Machine Identity naming/profile contracts
// owned by Keppin Machine Identity.
//
// The single production identity defined here produces persisted Windows
// machine state (a CNG/KSP key name). Changing it after first external release
// would create a parallel identity and require explicit migration/cleanup
// behaviour, so the exported value in this file must be treated as a
// compatibility contract once the first public release ships.
package identity

// ProdMachineIdentityKeyName is the full persisted production CNG machine
// identity (proof-of-possession) key name. This identity is stored in the
// Microsoft Software KSP and MUST NOT change after the first external release
// without an explicit migration procedure. It is Keppin-owned and must not use
// any other product namespace.
const ProdMachineIdentityKeyName = "Keppin.Agent.MachineIdentity.v1"
