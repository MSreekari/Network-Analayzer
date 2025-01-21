from django.shortcuts import render,redirect
from django.contrib.auth.models import User
from django.contrib.auth import authenticate,login as auth_login
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse
import os
import platform
from scapy.all import ARP, Ether, srp

def indexpage(request):

    return render(request,'networkapp/indexpage.html')

def signup(request):
    if request.method=='POST':
        uname = request.POST.get('username')
        email = request.POST.get('email')
        password = request.POST.get('password')
        cpassword = request.POST.get('confirm-password')

        if password!=cpassword:
            return HttpResponse("Your password and confirm password are not same!")
        else:
            my_user = User.objects.create_user(uname,email,password)
            my_user.save()
            return redirect('login')
    return render(request,'networkapp/signup.html')


def login(request):
    if request.method=='POST':
        uname = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(request,username=uname, password=password)
        if user is not None:
            auth_login(request, user)
            return redirect('')
        else:
            return HttpResponse("Invalid login credentials")
    return render(request,'networkapp/login.html')


def education(request):

    return render(request,'networkapp/education.html')

def features(request):

    return render(request, 'networkapp/features.html')

def networking_basics(request):

    return render(request, 'networkapp/networking-basics.html')

def network_scanning(request):

    return render(request, 'networkapp/network-scanning.html')

def cybersecurity_fundamentals(request):

    return render(request, 'networkapp/cybersecurity-fundamentals.html')

def hands_on_learning(request):

    return render(request, 'networkapp/hands-on-learning.html')

def networking_tools(request):

    return render(request, 'networkapp/networking-tools.html')

def glossary_of_terms(request):

    return render(request, 'networkapp/glossary-of-terms.html')

def dashboard(request):
    if request.user.is_authenticated:
        username = request.user.username
    else:
        username = "Guest"

    # Retrieve scan results and alert messages from session
    alert_message = request.session.get('alert_message', '')
    devices = request.session.get('devices', [])

    # Prepare results for rendering
    network_scan_result = f"{len(devices)} devices found" if devices else "No devices detected"
    
    return render(request, 'networkapp/dashboard.html', {
        'username': username,
        'alert_message': alert_message,
        'devices': devices,
        'network_scan_result': network_scan_result
    })

from django.http import JsonResponse

@login_required(login_url='login')
def scan(request):
    if request.method == "POST":
        ip_address = request.POST.get("ip_address")
        
        if not ip_address:
            return JsonResponse({"status": "IP address is required"}, status=400)

        # Determine the network range based on the IP address (using a simple subnet mask)
        # Here, we assume that the IP address is in the same subnet as 192.168.0.0/24
        # You can adjust the subnet calculation as needed based on the input IP
        ip_network = ".".join(ip_address.split(".")[:-1]) + ".0/24"
        
        # Create an ARP request to discover devices
        arp_request = ARP(pdst=ip_network)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        
        packet = broadcast/arp_request

        # Send the request and capture the response
        devices = []
        total_devices = len(devices)
        result = srp(packet, timeout=3, verbose=False)[0]
        
        for sent, received in result:
            devices.append({
                "ip": received.psrc,
                "mac": received.hwsrc,
                "hostname": received.psrc  # You can add DNS or other hostname resolution here
            })
        
        total_devices = len(devices)

        if devices:
            status = "Devices found"
            alert_message = "New devices detected!"
        else:
            status = f"No devices found for {ip_address}"
            alert_message = ""
        
        request.session['alert_message'] = alert_message
        request.session['devices'] = devices

        return JsonResponse({
            "status": status,
            "devices": devices,
            "alert_message": alert_message,
            "total_devices": total_devices
        })
    
    total_devices = len(request.session.get('devices', []))
    return render(request, 'networkapp/scan.html', {'total_devices': total_devices})

def ping_device(ip):
    if platform.system().lower() == "windows":
        response = os.system(f"ping -n 1 {ip}")
    else:
        response = os.system(f"ping -c 1 {ip}")

    return response == 0

def scanExternal(request):
    if request.method == "POST":
        ip_address = request.POST.get("ip_address")

        if not ip_address:
            return JsonResponse({"status": "IP address is required"}, status=400)

        # Use ICMP to ping the external IP
        is_up = ping_device(ip_address)
        status = f"Device {ip_address} is up" if is_up else f"Device {ip_address} is down"

        request.session['external_scan_result'] = status

        # Return only the status of the device (up or down)
        return JsonResponse({
            "status": status
        })

    return render(request, 'networkapp/scanExternal.html')
# def scan(request):
#     if request.method == "POST":
#         ip_address = request.POST.get("ip_address")

#         if not ip_address:
#             return JsonResponse({"status": "IP address is required"}, status=400)

#         # Perform the scan with Scapy
#         try:
#             packet = IP(dst=ip_address) / ICMP()
#             response = sr1(packet, timeout=2, verbose=0)  # Increase timeout to 2 seconds

#             if response is None:
#                 status = f"{ip_address} is inactive"
#                 round_trip_time = None  # No response, so no round trip time
#             else:
#                 # Extracting round-trip time
#                 round_trip_time = response.time  # This gives the round-trip time of the ping
#                 status = f"{ip_address} is active"

#             # Return both the status and round-trip time if available
#             return JsonResponse({
#                 "status": status,
#                 "round_trip_time": round_trip_time
#             })

#         except Exception as e:
#             status = f"Error: {str(e)}"
#             return JsonResponse({"status": status}, status=500)
    
#     return render(request, 'networkapp/scan.html')
