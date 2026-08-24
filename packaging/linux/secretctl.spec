Name: secretctl
Version: 0.1.0
Release: 1%{?dist}
Summary: Local credential isolation broker for agent authentication
License: Apache-2.0
Requires: libsecret

%description
Linux low/medium-risk secretctl package using Secret Service. High-risk actions
fail with user_presence_unavailable.

%install
install -D -m0755 secretctl %{buildroot}%{_bindir}/secretctl
install -D -m0755 secretctld %{buildroot}%{_libexecdir}/secretctl/secretctld
install -D -m0755 secretctl-native-host %{buildroot}%{_libexecdir}/secretctl/secretctl-native-host
install -D -m0644 packaging/linux/secretctld.service %{buildroot}%{_userunitdir}/secretctld.service

%files
%{_bindir}/secretctl
%{_libexecdir}/secretctl/secretctld
%{_libexecdir}/secretctl/secretctl-native-host
%{_userunitdir}/secretctld.service
