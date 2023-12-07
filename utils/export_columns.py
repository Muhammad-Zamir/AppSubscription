NOTIFICATION_EXPORT_COLUMNS = ["Name", "Subject", "Body", "is_published", "Recipient List", "Recipient Roles", "Recipient Group"]
DEPARTMENT_EXPORT_COLUMNS = ["Name", "Detail", "Category", "Date Created"]
SUB_DEPARTMENT_EXPORT_COLUMNS = ["Name", "Detail", "Category", "Date Created", "Department"]
DESIGNATION_EXPORT_COLUMNS = ["Name", "Detail", "Department", "Date Created"]
EMPLOYEE_EXPORT_COLUMNS = [
    "Name",
    "Date of Birth",
    "Email",
    "Gender",
    "Contact Number",
    "Emergency Contact Number",
    "Emergency Contact Name",
    "Address",
    "Date of joining",
    "SAP ID",
    "Department",
    "Designation",
    "Grade",
    "Date Created",
    "Subzone",
    "Zone",
    "City",
    "Region",
    "Country",
    "Reports to",
    "Start Time",
    "End Time"
]
USER_EXPORT_COLUMNS = [
    "Name",
    "Username",
    "Email",
    "Date Created",
    "Employee ID",
    "Status"
]
REGION_EXPORT_COLUMNS = ["Name", "Code","Country"]
COUNTRY_EXPORT_COLUMNS = ["Name", "Code"]
CITY_EXPORT_COLUMNS = ["Name", "Code", "Region", "Country"]
ZONE_EXPORT_COLUMNS = ["Name", "Code", "City", "Region", "Country"]
SUBZONE_EXPORT_COLUMNS = ["Name", "Code", "Zone", "City", "Region", "Country"]
PRODUCT_EXPORT_COLUMNS = [
    "Name",
    "Code",
    "Description",
    "Category",
    "Image",
    "Manufacturer",
    "Weight",
    "Dimensions",
    "Product_Type"
]
PRODUCT_TYPE_EXPORT_COLUMNS = [
    "Name",
    "Code",
    "Description"
]
BRAND_EXPORT_COLUMNS = ["Name", "Code", "Brand_Type"]
BRAND_TYPE_EXPORT_COLUMNS = ["Name", "Code", "Description", "Region", "Country"]
GRADE_EXPORT_COLUMNS = ["Prefix", "Number"]
WAREHOUSE_EXPORT_COLUMNS = [
    "Name",
    "Country",
    "Region",
    "City",
    "Zone",
    "Address",
    "Person in charge",
    "Items_capacity",
    "Warehouse_square_footage",
    "product count",
    "Storage_types",
    "Loading_unloading_info",
    "Operating_hours",
    "Sap_id",
    "Longitude",
    "Latitude",
    "Additional_information",
    "Code",
    "Category",
]
PLANT_EXPORT_COLUMNS = [
    "Name",
    "Country",
    "Region",
    "City",
    "Address",
    "Person in Charge",
    "Manufacturing_capacity",
    "Storage_capacity",
    "Product count",
    "Storage_types",
    "Loading_unloading_info",
    "Security_control_mechanism",
    "Operating_hours",
    "Sap_id",
    "Longitude",
    "Latitude",
    "Additional_information",
    "Code",
]
OUTLET_EXPORT_COLUMNS = [
    "SAP_ID",
    "Business Name",
    "NTN",
    "STRN",
    "Address",
    "Owner Name",
    "Owner CNIC",
    "Email",
    "Owner contact",
    "Longitude",
    "Latitude",
    "Category",
    "Country",
    "Region",
    "City",
    "Zone",
    "Subzone",
    "Channel",
    "Login",
]

CHANNEL_EXPORT_COLUMNS = ["Name", "Code", "Created_at"]
USER_GROUP_EXPORT_COLUMNS = ["Name", "Users"]
EMAIL_EXPORT_COLUMNS = []
ROLE_EXPORT_COLUMNS = ["Name", "Features", "Status"]


LAUNCHED_PRODUCT_EXPORT_COLUMNS = [
    "Name",
    "Code",
    "Description",
    "Category",
    "Image",
    "Manufacturer",
    "Weight",
    "Dimensions",
    "Product_Type",
    "Country",
    "Region",
    "City",
    "Zone",
    "Subzone",
    "Channel",

]

AREA_VIOLATION_EXPORT_COLUMNS = ["Outlet", "Reported Zone", "Stock Origin Outlet", "Relevent Distributer","Description","Evidence","Fine","Date","Code", "Outlet_id", "Reported_Zone_id","Stock_Origin_id","Relevant_Distributor_id"]
DO_EXPORT_COLUMNS = ["Date Created","Is Active", "Document Date", "Customer Sap ID", "Document number", "Document Type", "Product", "Status", "Customer", "Contract Number", "Order Number" , "Quantity", "Delivery Challan", "Unit", "Assigned Outlet"]
