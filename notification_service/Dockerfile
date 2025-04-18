# Step 1: Use an official Python image as a base image
FROM python:3.9-slim
# Step 2: Set the working directory inside the container
WORKDIR /app
# Step 3: Copy the requirements file into the container
COPY notification_service/requirements.txt /app/
# Step 4: Install the dependencies
RUN pip install --no-cache-dir -r requirements.txt
# Step 5: Copy the rest of the application code
COPY notification_service/ /app/
# Step 6: Set environment variables (optional)
ENV PYTHONUNBUFFERED 1
# Step 7: Expose the port that FastAPI will run on
EXPOSE 8000
# Step 8: Command to run the FastAPI app with Uvicorn
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]