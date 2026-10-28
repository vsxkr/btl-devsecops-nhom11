# =============================================================================
# docker_runtime.rb — Compliance as Code cho container dang chay.
#
# Can cu: Hands-on_guide_updated.docx Phase 6 va moc cham so 5:
#   "Profile executes against the running container; students explain each
#    control and a deliberate failure case."
#
# Cach chay (tren HOST, dung local transport, doc `docker inspect`):
#   inspec exec compliance --input container=ilfreight_web --chef-license=accept-silent
# Hoac khong can cai InSpec:
#   docker run --rm -v /var/run/docker.sock:/var/run/docker.sock:ro \
#     -v "$PWD/compliance:/profile" chef/inspec exec /profile \
#     --input container=ilfreight_web --chef-license=accept-silent
#
# Vi sao doc `docker inspect` thay vi dung transport docker:// : anh php:8.2-apache
# va mariadb:10.11 khong chac co du tien ich shell cho transport do, con
# `docker inspect` luon cho cung mot ket qua tren moi anh.
# =============================================================================

container = input('container', value: 'ilfreight_web')

inspect_json = json(command: "docker inspect #{container}")
cfg = inspect_json.params.first

control 'ilf-run-01-non-root' do
  impact 1.0
  title 'Container khong chay bang root'
  desc "Yeu cau an toan toi thieu: tien trinh trong container khong duoc la root. " \
       "Doi chieu CIS Docker 4.1 va PCI DSS 2.2. Neu Dockerfile khong co lenh USER " \
       "va compose khong dat `user:` thi truong Config.User rong, tuc chay bang root."
  describe "Config.User cua #{container}" do
    subject { cfg.dig('Config', 'User') }
    it { should_not be_nil }
    it { should_not eq '' }
    it { should_not match(/^(root|0)(:|$)/) }
  end
end

control 'ilf-run-02-least-privilege' do
  impact 1.0
  title 'Khong dac quyen, khong leo thang dac quyen, bo het capability'
  desc "Doi chieu CIS Docker 5.3, 5.4 va 5.25. Ba truong nay tuong ung voi " \
       "`privileged`, `security_opt: no-new-privileges:true` va `cap_drop: [ALL]` " \
       "trong tep compose."
  describe 'HostConfig.Privileged' do
    subject { cfg.dig('HostConfig', 'Privileged') }
    it { should eq false }
  end
  describe 'HostConfig.SecurityOpt' do
    subject { cfg.dig('HostConfig', 'SecurityOpt') || [] }
    it { should include 'no-new-privileges:true' }
  end
  describe 'HostConfig.CapDrop' do
    subject { cfg.dig('HostConfig', 'CapDrop') || [] }
    it { should include 'ALL' }
  end
end

control 'ilf-run-03-network-exposure' do
  impact 0.7
  title 'Moi cong da cong bo chi buoc vao loopback'
  desc "Doi chieu GDPR Dieu 32. Dich phia truoc la reverse proxy, nen khong co " \
       "dich vu nao can lang nghe tren moi giao dien. Day la kiem soat tuong ung " \
       "voi luat ATTACK-SURFACE trong policy/compose_security.rego, nhung do o " \
       "trang thai chay thuc te chu khong o tep cau hinh."
  bindings = cfg.dig('HostConfig', 'PortBindings') || {}
  if bindings.empty?
    describe 'PortBindings' do
      it 'khong cong bo cong nao, dat' do
        expect(bindings).to be_empty
      end
    end
  else
    bindings.each do |port, binds|
      (binds || []).each_with_index do |b, i|
        describe "cong #{port} rang buoc thu #{i + 1}" do
          subject { b['HostIp'] }
          it { should eq '127.0.0.1' }
        end
      end
    end
  end
end

control 'ilf-run-04-no-secrets-in-env' do
  impact 1.0
  title 'Khong co thong tin xac thuc trong bien moi truong cua container'
  desc "Doi chieu PCI DSS 8.6.2 va GDPR Dieu 32. Bien moi truong cua container " \
       "doc duoc bang `docker inspect` va hien trong moi ban ghi su kien, nen bi mat " \
       "dat o day la bi mat da bi tiet lo. Kiem soat nay la phien ban thoi diem chay " \
       "cua luat CREDENTIALS trong policy/compose_security.rego."
  env = cfg.dig('Config', 'Env') || []
  describe 'bien moi truong co ten giong thong tin xac thuc' do
    subject { env.grep(/(^|_)(PASS|PASSWORD|PASSWD|SECRET|TOKEN|API_KEY|CREDENTIAL)=/i) }
    it { should be_empty }
  end
end

control 'ilf-run-05-no-docker-socket' do
  impact 1.0
  title 'Khong mount socket cua Docker vao container'
  desc "Doi chieu CIS Docker 5.31. Quyen ghi vao /var/run/docker.sock tuong duong " \
       "quyen root tren may chu, vi tien trinh trong container co the tao mot " \
       "container khac co dac quyen."
  mounts = cfg['Mounts'] || []
  describe 'mount tro toi docker.sock' do
    subject { mounts.select { |m| m['Source'].to_s.include?('docker.sock') } }
    it { should be_empty }
  end
end

control 'ilf-run-06-readonly-rootfs' do
  impact 0.5
  title 'He tep goc nen o che do chi doc'
  desc "Doi chieu CIS Docker 5.12. Day la kiem soat muc khuyen nghi, tuong ung voi " \
       "canh bao `read_only` trong policy/compose_security.rego. Duong ghi can thiet " \
       "nen duoc cap qua tmpfs."
  describe 'HostConfig.ReadonlyRootfs' do
    subject { cfg.dig('HostConfig', 'ReadonlyRootfs') }
    it { should eq true }
  end
end
