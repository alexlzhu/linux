%define has_kver %{?rpm_kernel_version: 1} %{?!rpm_kernel_version: 0}
%if !%{has_kver}
%define rpm_kernel_version %(uname -r)
%endif

Name:	klp-%{rpm_kernel_version}
Version: %{hf_name}
Release: r1
Summary: kernel live patch version
Requires: kpatch

Group: System Environment/Kernel
License: GPL
URL: http://www.kernel.org

%prep
mkdir -p $RPM_BUILD_ROOT/var/lib/kpatch/%{rpm_kernel_version}/
cp %{module_path} $RPM_BUILD_ROOT/var/lib/kpatch/%{rpm_kernel_version}/klp_%{rpm_kernel_version}.ko

%files
/var/lib/kpatch/%{rpm_kernel_version}/klp_%{rpm_kernel_version}.ko

%post
kpatch load --all

%postun

%description
Kernel live patch module for a hotfix %{hf_name} for a version %{rpm_kernel_version}
