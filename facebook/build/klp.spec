%define has_kver %{?rpm_kernel_version: 1} %{?!rpm_kernel_version: 0}
%if !%{has_kver}
%define rpm_kernel_version %(uname -r)
%endif

Name:	klp-%{rpm_kernel_version}
Version: %{hf_name}
Release: r1
Summary: kernel live patch version

Group: System Environment/Kernel
License: GPL	
URL: http://www.kernel.org

%prep
mkdir -p $RPM_BUILD_ROOT/lib/modules/%{rpm_kernel_version}/extra/klp/
cp %{module_path} $RPM_BUILD_ROOT/lib/modules/%{rpm_kernel_version}/extra/klp/klp_%{rpm_kernel_version}_%{hf_name}.ko

%files
/lib/modules/%{rpm_kernel_version}/extra/klp/klp_%{rpm_kernel_version}_%{hf_name}.ko

%post
/sbin/depmod -a %{rpm_kernel_version}

%postun
/sbin/depmod -a %{rpm_kernel_version}

%description
Kernel live patch module for a hotfix %{hf_name} for a version %{rpm_kernel_version}
