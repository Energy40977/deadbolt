"""Statement export endpoint."""

# The pattern has no context requirement, so the import of the permission class
# reads the same as its use. Pinned rather than fixed: an import of AllowAny is
# weak evidence, not no evidence.
# deadbolt-noise DB-AUN-001:high
from rest_framework.permissions import AllowAny
from rest_framework.views import APIView


class StatementExport(APIView):
    # deadbolt-expect DB-AUN-001:high
    permission_classes = [AllowAny]
