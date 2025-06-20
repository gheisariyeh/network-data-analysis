import pyshark
import pandas as pd
import folium
from folium.plugins import HeatMap
import geoip2.database
import os

# Function to get geolocation information for an IP
def get_geolocation(ip, reader):
    try:
        response = reader.city(ip)
        return response.location.latitude, response.location.longitude
    except:
        return None, None

# Read the PCAP file and extract source IP geolocations
def parse_pcap(file_path, geoip_db_path):
    cap = pyshark.FileCapture(file_path)
    
    geo_data = {'latitude': [], 'longitude': []}
    
    # Open the GeoIP database
    reader = geoip2.database.Reader(geoip_db_path)
    
    for packet in cap:
        try:
            # Extract source IP from the packet
            if hasattr(packet, 'ip'):
                src_ip = packet.ip.src
                lat, lon = get_geolocation(src_ip, reader)
                if lat and lon:
                    geo_data['latitude'].append(lat)
                    geo_data['longitude'].append(lon)
        except AttributeError:
            continue
    
    # Close the GeoIP database
    reader.close()
    
    return pd.DataFrame(geo_data)

# Create a heatmap from the collected geolocation data
def create_heatmap(geo_df):
    attack = geo_df[['latitude', 'longitude']]
    
    # Fill missing values to avoid warnings
    attack['latitude'] = attack['latitude'].fillna(0)
    attack['longitude'] = attack['longitude'].fillna(0)

    # Initialize world map
    World = folium.Map(location=[0, 0], zoom_start=2)
    HeatMap(data=attack, radius=16).add_to(World)

    print('Top cyberattacks by country')
    return World

# Get the directory of the current script
script_dir = os.path.dirname(os.path.abspath(__file__))

# PCAP file path placeholder
pcap_file = "Path to the PCAP file"
if pcap_file == "Path to the PCAP file":
    raise ValueError("⚠️ Please set `pcap_file` to the actual path of your .pcap file before running.")

# GeoIP database path placeholder
geoip_db = "Path to the GeoIP database file"
if geoip_db == "Path to the GeoIP database file":
    raise ValueError("⚠️ Please set `geoip_db` to the actual path of your GeoIP .mmdb file before running.")

# Process the PCAP and generate the heatmap
geo_df = parse_pcap(pcap_file, geoip_db)
heatmap = create_heatmap(geo_df)

# Save the heatmap HTML in the script directory
output_path = os.path.join(script_dir, 'cyberattack_heatmap.html')
heatmap.save(output_path)

print(f'Heatmap saved as "{output_path}"')
