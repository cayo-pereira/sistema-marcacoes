document.addEventListener("DOMContentLoaded", function () {
    const dateInput = document.getElementById("data");
    const timeInput = document.getElementById("horario");

    dateInput.addEventListener("change", function () {
        const selectedDate = new Date(dateInput.value);
        if (selectedDate.getDay() === 6 || selectedDate.getDay() === 0) {
            alert("As consultas só ocorrem de segunda a sexta-feira.");
            dateInput.value = "";
        }
    });

    timeInput.addEventListener("change", function () {
        const selectedTime = timeInput.value;
        if (["12:00", "12:30"].includes(selectedTime)) {
            alert("Este horário não está disponível devido ao horário de almoço.");
            timeInput.value = "";
        }
    });
});
