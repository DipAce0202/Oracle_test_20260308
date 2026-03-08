import oci
import time
import datetime
import os
import sys

# ─── SECURE CONFIG (Read from Environment Variables / GitHub Secrets) ───────────────────────────────────────────────
COMPARTMENT_ID = os.environ.get("OCI_COMPARTMENT_OCID")
SSH_PUBLIC_KEY = os.environ.get("MY_PUBLIC_SSH_KEY")
REGION = os.environ.get("OCI_REGION")
USER_OCID = os.environ.get("OCI_USER_OCID")
TENANCY_OCID = os.environ.get("OCI_TENANCY_OCID")
FINGERPRINT = os.environ.get("OCI_FINGERPRINT")
PRIVATE_KEY_PATH = os.path.expanduser("~/.oci/oci_api_key.pem")

# Retry Settings
RETRY_INTERVAL = 90  # seconds
MAX_ATTEMPTS = 20    # Prevent infinite loops (important for GitHub Actions)

# Instance Settings (Conservative for better capacity success)
INSTANCE_SHAPE = "VM.Standard.A1.Flex"
INSTANCE_OCPUS = 1
INSTANCE_MEMORY = 6
BOOT_VOLUME_SIZE = 50  # GB (Free Tier gives 200GB total)
INSTANCE_DISPLAY_NAME = f"GitHub-Ampere-{datetime.datetime.now().strftime('%Y%m%d-%H%M%S')}"

# Validate required secrets
required_secrets = [
    "OCI_COMPARTMENT_OCID",
    "OCI_REGION",
    "OCI_USER_OCID",
    "OCI_TENANCY_OCID",
    "OCI_FINGERPRINT",
    "MY_PUBLIC_SSH_KEY"
]

for secret in required_secrets:
    if not os.environ.get(secret):
        print(f"❌ Missing required secret: {secret}")
        sys.exit(1)

print("✅ All required secrets found")
# ────────────────────────────────────────────────────────

# Setup Config for OCI SDK
config = {
    "user": USER_OCID,
    "fingerprint": FINGERPRINT,
    "tenancy": TENANCY_OCID,
    "region": REGION,
    "key_file": PRIVATE_KEY_PATH,
}

def get_availability_domain():
    """Fetch the first available Availability Domain"""
    print("🔍 Fetching Availability Domain...")
    identity = oci.identity.IdentityClient(config)
    ads = identity.list_availability_domains(COMPARTMENT_ID).data
    if not ads:
        raise Exception("No Availability Domains found")
    ad_name = ads[0].name
    print(f"   Selected AD: {ad_name}")
    return ad_name

def get_arm_image():
    """Fetch the latest Oracle Linux ARM image"""
    print("🔍 Fetching ARM Image...")
    compute = oci.core.ComputeClient(config)
    images = compute.list_images(
        COMPARTMENT_ID,
        operating_system="Oracle-Linux",
        shape="VM.Standard.A1.Flex",
        sort_by="TIMECREATED",
        sort_order="DESC",
    ).data
    
    if not images:
        # Fallback to Ubuntu if Oracle Linux not found
        print("   Oracle Linux not found, trying Ubuntu...")
        images = compute.list_images(
            COMPARTMENT_ID,
            operating_system="Canonical Ubuntu",
            operating_system_version="22.04",
            shape="VM.Standard.A1.Flex",
            sort_by="TIMECREATED",
            sort_order="DESC",
        ).data
    
    if not images:
        raise Exception("No ARM Image found for Oracle-Linux or Ubuntu")
    
    image_id = images[0].id
    image_name = images[0].display_name
    print(f"   Selected Image: {image_name}")
    print(f"   Image OCID: {image_id}")
    return image_id

def create_vcn_and_subnet():
    """Create VCN, Internet Gateway, and Subnet if they don't exist"""
    print("🔧 Setting up Network (VCN + Subnet)...")
    network = oci.core.VirtualNetworkClient(config)
    
    vcn_name = "github-actions-vcn"
    subnet_name = "github-actions-subnet"
    ig_name = "github-actions-ig"

    # ─── Check/Create VCN ───
    vcns = network.list_vcns(COMPARTMENT_ID, display_name=vcn_name).data
    if vcns:
        vcn = vcns[0]
        print(f"   ✅ Using existing VCN: {vcn.id}")
    else:
        print("   📦 Creating new VCN...")
        vcn = network.create_vcn(
            oci.core.models.CreateVcnDetails(
                compartment_id=COMPARTMENT_ID,
                display_name=vcn_name,
                cidr_block="10.0.0.0/16",
            )
        ).data
        print(f"   ✅ Created VCN: {vcn.id}")

    # ─── Check/Create Internet Gateway ───
    igw_list = network.list_internet_gateways(COMPARTMENT_ID, vcn_id=vcn.id, display_name=ig_name).data
    if igw_list:
        ig = igw_list[0]
        print(f"   ✅ Using existing Internet Gateway: {ig.id}")
    else:
        print("   📦 Creating Internet Gateway...")
        ig = network.create_internet_gateway(
            oci.core.models.CreateInternetGatewayDetails(
                compartment_id=COMPARTMENT_ID,
                vcn_id=vcn.id,
                display_name=ig_name,
                is_enabled=True,
            )
        ).data
        print(f"   ✅ Created Internet Gateway: {ig.id}")

    # ─── Update Route Table (if needed) ───
    route_table = network.get_route_table(vcn.default_route_table_id).data
    has_internet_route = any(
        rule.destination == "0.0.0.0/0" and rule.network_entity_id == ig.id
        for rule in route_table.route_rules
    )
    
    if not has_internet_route:
        print("   🛣️  Updating Route Table...")
        network.update_route_table(
            vcn.default_route_table_id,
            oci.core.models.UpdateRouteTableDetails(
                route_rules=[
                    oci.core.models.RouteRule(
                        destination="0.0.0.0/0",
                        network_entity_id=ig.id,
                    )
                ]
            ),
        )
        print("   ✅ Route Table updated")
    else:
        print("   ✅ Route Table already configured")

    # ─── Update Security List (Open SSH, HTTP, HTTPS) ───
    security_lists = network.list_security_lists(COMPARTMENT_ID, vcn_id=vcn.id).data
    if security_lists:
        sec_list = security_lists[0]
        print("   🔓 Updating Security List (opening ports 22, 80, 443)...")
        
        existing_egress = sec_list.egress_security_rules or []
        new_ingress = []
        
        for port in [22, 80, 443]:
            new_ingress.append(
                oci.core.models.IngressSecurityRule(
                    protocol="6",  # TCP
                    source="0.0.0.0/0",
                    tcp_options=oci.core.models.TcpOptions(
                        destination_port_range=oci.core.models.PortRange(
                            min=port, max=port
                        )
                    ),
                )
            )
        
        network.update_security_list(
            sec_list.id,
            oci.core.models.UpdateSecurityListDetails(
                ingress_security_rules=new_ingress,
                egress_security_rules=existing_egress,
            ),
        )
        print("   ✅ Security List updated")

    # ─── Check/Create Subnet ───
    subnets = network.list_subnets(COMPARTMENT_ID, vcn_id=vcn.id, display_name=subnet_name).data
    if subnets:
        subnet = subnets[0]
        print(f"   ✅ Using existing Subnet: {subnet.id}")
    else:
        print("   📦 Creating Subnet...")
        subnet = network.create_subnet(
            oci.core.models.CreateSubnetDetails(
                compartment_id=COMPARTMENT_ID,
                vcn_id=vcn.id,
                display_name=subnet_name,
                cidr_block="10.0.0.0/24",
                prohibit_public_ip_on_vnic=False,
            )
        ).data
        print(f"   ✅ Created Subnet: {subnet.id}")

    return subnet.id

def try_create_instance(subnet_id, ad_name, image_id):
    """Launch the Ampere instance"""
    print("🚀 Launching Instance...")
    compute = oci.core.ComputeClient(config)
    
    instance = compute.launch_instance(
        oci.core.models.LaunchInstanceDetails(
            compartment_id=COMPARTMENT_ID,
            display_name=INSTANCE_DISPLAY_NAME,
            availability_domain=ad_name,
            shape=INSTANCE_SHAPE,
            shape_config=oci.core.models.LaunchInstanceShapeConfigDetails(
                ocpus=INSTANCE_OCPUS,
                memory_in_gbs=INSTANCE_MEMORY,
            ),
            source_details=oci.core.models.InstanceSourceViaImageDetails(
                image_id=image_id,
                boot_volume_size_in_gbs=BOOT_VOLUME_SIZE,
            ),
            create_vnic_details=oci.core.models.CreateVnicDetails(
                subnet_id=subnet_id,
                assign_public_ip=True,
            ),
            metadata={"ssh_authorized_keys": SSH_PUBLIC_KEY},
        )
    ).data
    
    return instance

def main():
    print("=" * 60)
    print("🛠️  Oracle Ampere Instance Automation (Python SDK)")
    print("=" * 60)
    
    try:
        # Step 1: Setup Network
        subnet_id = create_vcn_and_subnet()
        
        # Step 2: Get Availability Domain
        ad_name = get_availability_domain()
        
        # Step 3: Get ARM Image
        image_id = get_arm_image()
        
        # Step 4: Try to create instance with retries
        print("\n" + "=" * 60)
        print("🔄 Starting Instance Creation with Retry Logic")
        print("=" * 60)
        
        attempt = 0
        success = False
        
        while attempt < MAX_ATTEMPTS:
            attempt += 1
            now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            print(f"\n[{now}] Attempt {attempt}/{MAX_ATTEMPTS}...")
            print("-" * 60)

            try:
                instance = try_create_instance(subnet_id, ad_name, image_id)
                
                print("\n" + "=" * 60)
                print("✅ SUCCESS! Instance Created")
                print("=" * 60)
                print(f"   Instance ID: {instance.id}")
                print(f"   Display Name: {instance.display_name}")
                print(f"   Lifecycle State: {instance.lifecycle_state}")
                print(f"   Shape: {instance.shape}")
                print(f"   AD: {instance.availability_domain}")
                print("=" * 60)
                print("📌 Next Steps:")
                print("   1. Go to OCI Console > Compute > Instances")
                print("   2. Find your instance and note the Public IP")
                print(f"   3. SSH: ssh -i ~/.ssh/id_rsa opc@<PUBLIC_IP>")
                print("=" * 60)
                
                success = True
                break
                
            except oci.exceptions.ServiceError as e:
                error_msg = str(e)
                if "capacity" in error_msg.lower() or "out of host" in error_msg.lower():
                    print(f"❌ Out of Capacity (Error Code: {e.code})")
                    print(f"   ⏳ Waiting {RETRY_INTERVAL} seconds before retry...")
                elif "notauthorized" in error_msg.lower():
                    print(f"🚨 Authentication Error: {e.message}")
                    print("   Check your API Key and Secrets!")
                    break
                else:
                    print(f"❌ Service Error: {e.message} (Code: {e.code})")
                    print(f"   ⏳ Waiting {RETRY_INTERVAL} seconds before retry...")
            
            except Exception as e:
                print(f"⚠️ Unexpected Error: {type(e).__name__}: {str(e)}")
                print(f"   ⏳ Waiting {RETRY_INTERVAL} seconds before retry...")
            
            time.sleep(RETRY_INTERVAL)
        
        if not success:
            print("\n" + "=" * 60)
            print(f"⚠️  FAILED after {MAX_ATTEMPTS} attempts")
            print("=" * 60)
            print("💡 Tips:")
            print("   - Try a different region (e.g., us-phoenix-1, eu-frankfurt-1)")
            print("   - Try running at off-peak hours (night/weekend)")
            print("   - Reduce OCPUs/Memory in the script")
            print("=" * 60)
            sys.exit(1)
            
    except Exception as e:
        print(f"\n🚨 Critical Error: {type(e).__name__}: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
